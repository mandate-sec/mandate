"""Boot the built image and PostgreSQL on an internal network; no target scans."""
import hashlib
import json
import os
import secrets
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

IMAGE = sys.argv[1] if len(sys.argv) > 1 else 'failsafe-security/artex:ci'
PG_IMAGE = 'postgres:16-alpine@sha256:0cefaabd882e42bcb2a2f3dc56d3ce4770560ba62fd7f197f1a2e008fd5731ab'
name = 'artex-smoke-' + uuid.uuid4().hex[:10]
pg, app, data, keys = (name + suffix for suffix in ('-pg', '-app', '-data', '-keys'))


def docker(*args, check=True, input=None):
    result = subprocess.run(['docker', *args], input=input, text=True, capture_output=True, timeout=180)
    if check and result.returncode:
        raise RuntimeError(f'docker {args[0]} failed ({result.returncode}):\n{result.stdout}\n{result.stderr}')
    return result


def api(path, method='GET', payload=None, token=None):
    # Send credentials over stdin so they cannot appear in process listings or timeout errors.
    program = '''import json,sys,urllib.request,urllib.error
PATH,METHOD,PAYLOAD,TOKEN=json.load(sys.stdin)
request=urllib.request.Request('http://127.0.0.1:8787'+PATH,method=METHOD,
 data=None if PAYLOAD is None else json.dumps(PAYLOAD).encode(),
 headers={'Content-Type':'application/json',**({'Authorization':'Bearer '+TOKEN} if TOKEN else {})})
try:
 response=urllib.request.urlopen(request,timeout=10)
except urllib.error.HTTPError as error:
 response=error
raw=response.read().decode()
try: body=json.loads(raw)
except ValueError: body=raw
print(json.dumps({'status':response.status,'body':body}))
'''
    request_data = json.dumps([path, method, payload, token])
    return json.loads(docker('exec', '-i', app, 'python3', '-c', program, input=request_data).stdout)


def expect(result, status):
    assert result['status'] == status, f'Expected HTTP {status}, got {result["status"]}'
    return result['body']


def start_postgres_compose(directory):
    # Exercise the real Compose recovery path without touching a checkout's
    # configuration or any similarly named running service.
    (directory / '.env.safe').write_text('', encoding='utf-8')
    config = {
        'name': name,
        'services': {
            'postgres': {
                'image': PG_IMAGE,
                'container_name': pg,
                'environment': {
                    'POSTGRES_USER': 'artex',
                    'POSTGRES_PASSWORD': 'smoke-db-fixture',
                    'POSTGRES_DB': 'artex',
                },
                'networks': ['fixture'],
            },
        },
        'networks': {'fixture': {'name': name, 'external': True}},
    }
    manifest = directory / 'docker-compose.safe.yml'
    manifest.write_text(json.dumps(config), encoding='utf-8')
    docker('compose', '--project-name', name, '-f', str(manifest), 'up', '-d', 'postgres')


def revoke_sessions_with_compose(directory):
    recovery = Path(__file__).resolve().parents[1] / 'reset-password.sh'
    env = os.environ.copy()
    for key in ('PGUSER', 'PGPASSWORD', 'PGDATABASE', 'POSTGRES_USER', 'POSTGRES_PASSWORD', 'POSTGRES_DB'):
        env.pop(key, None)
    env['COMPOSE_PROJECT_NAME'] = name
    result = subprocess.run(
        ['bash', str(recovery), '-m', 'docker', '--exec', 'compose', '--revoke-sessions', '--yes'],
        cwd=directory, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=45,
    )
    if result.returncode:
        raise RuntimeError(f'Compose session revocation failed (exit {result.returncode}): {result.stderr}')


compose_fixture = tempfile.TemporaryDirectory(prefix='mandate-smoke-compose-')
compose_dir = Path(compose_fixture.name)
try:
    setup_token = secrets.token_hex(32)
    docker('network', 'create', '--internal', name)
    for volume in (data, keys):
        docker('volume', 'create', volume)
    start_postgres_compose(compose_dir)
    for attempt in range(60):
        if docker('exec', pg, 'pg_isready', '-U', 'artex', check=False).returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError('PostgreSQL did not become ready')
    docker('run', '-d', '--name', app, '--network', name,
           '--read-only', '--tmpfs', '/tmp:size=1g,mode=1777',
           '--tmpfs', '/home/mandate:size=256m,uid=10001,gid=10001,mode=0700',
           '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--shm-size=1g',
           '-e', 'MANDATE_SETUP_TOKEN_SHA256=' + hashlib.sha256(setup_token.encode()).hexdigest(),
           '-e', f'ARTEX_PG_DSN=postgres://artex:smoke-db-fixture@{pg}:5432/artex?sslmode=disable',
           '-v', data + ':/app/data', '-v', keys + ':/app/keys',
           '-v', str(Path(__file__).resolve().parent) + ':/ci:ro', IMAGE)
    for attempt in range(90):
        if docker('exec', app, 'curl', '-fsS', 'http://127.0.0.1:8787/api/health', check=False).returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError('ARTEX did not become healthy')
    expect(api('/'), 200)
    expect(api('/api/tasks'), 401)
    password = 'ARTEX-smoke-fixture-2026!'
    expect(api('/api/auth/init', 'POST', {'password': password}), 403)
    token = expect(api('/api/auth/init', 'POST', {'password': password, 'setupToken': setup_token}), 200)['token']
    expect(api('/api/auth/login', 'POST', {'username': 'ARTEX', 'password': 'wrong', 'captcha': 'smoke-canary'}), 401)
    expect(api('/api/auth/login', 'POST', {'username': 'ARTEX', 'password': password}), 200)
    expect(api('/api/tasks', token=token), 200)
    update = expect(api('/api/update/check?force=1', token=token), 200)
    assert update['disabled'] is True and update['has_update'] is False
    expect(api('/api/update/apply', 'POST', {}, token), 403)
    expect(api('/api/update/rollback', 'POST', {}, token), 403)
    print(docker('exec', app, 'node', '/ci/api-recon-smoke.js').stdout.strip())
    print(docker('exec', app, 'node', '/ci/browser-mcp-smoke.cjs').stdout.strip())
    assert docker('inspect', '--format', '{{.HostConfig.ReadonlyRootfs}}', app).stdout.strip() == 'true'
    assert docker('exec', app, 'id', '-u').stdout.strip() == '10001'
    status_lines = docker('exec', app, 'cat', '/proc/1/status').stdout.splitlines()
    status = dict(line.split(':', 1) for line in status_lines if ':' in line)
    for field in ('CapEff', 'CapPrm', 'CapBnd', 'CapAmb'):
        assert int(status[field], 16) == 0, field
    assert status['NoNewPrivs'].strip() == '1'
    temporary_markers = ('/tmp/mandate-restart-check', '/home/mandate/mandate-restart-check')
    docker('exec', app, 'touch', *temporary_markers)
    assert docker('exec', app, 'test', '-w', '/app/artex', check=False).returncode == 1
    stopped = time.monotonic()
    docker('stop', '--time', '15', app)
    state = json.loads(docker('inspect', '--format', '{{json .State}}', app).stdout)
    assert state['ExitCode'] == 0 and not state['OOMKilled'], state
    print(f'Graceful SIGTERM: exit 0 in {time.monotonic() - stopped:.2f}s')
    docker('start', app)
    for attempt in range(60):
        if docker('exec', app, 'curl', '-fsS', 'http://127.0.0.1:8787/api/health', check=False).returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError('ARTEX did not become healthy after restart')
    for marker in temporary_markers:
        docker('exec', app, 'test', '!', '-e', marker)
    expect(api('/api/tasks', token=token), 200)
    print('Runtime smoke: embedded UI, PostgreSQL, auth, updater, browsers, unprivileged runtime, shutdown and persisted JWT passed')
    new_password = secrets.token_urlsafe(24)
    expect(api('/api/auth/change-password', 'POST', {'old_password': password, 'new_password': new_password}, token), 200)
    expect(api('/api/tasks', token=token), 401)
    expect(api('/api/auth/login', 'POST', {'username': 'ARTEX', 'password': password}), 401)
    fresh = expect(api('/api/auth/login', 'POST', {'username': 'ARTEX', 'password': new_password}), 200)['token']
    expect(api('/api/tasks', token=fresh), 200)
    revoke_sessions_with_compose(compose_dir)
    expect(api('/api/tasks', token=fresh), 401)
    renewed = expect(api('/api/auth/login', 'POST', {'username': 'ARTEX', 'password': new_password}), 200)['token']
    expect(api('/api/tasks', token=renewed), 200)
    print('Compose session revocation rejected the old token and preserved the administrator password')
except Exception:
    for container in (app, pg):
        print(docker('logs', '--tail', '80', container, check=False).stderr, file=sys.stderr)
    raise
finally:
    for container in (app, pg):
        docker('rm', '-f', '-v', container, check=False)
    docker('network', 'rm', name, check=False)
    for volume in (data, keys):
        docker('volume', 'rm', volume, check=False)
    compose_fixture.cleanup()
