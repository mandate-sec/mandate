"""Run every Go test with a fresh PostgreSQL database and process.

Several packages persist task/provider fixtures and start background managers.
Separate processes and databases prevent those fixtures from affecting another
test. Test discovery is automatic: no failing test is filtered out.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.parse
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('--output', default='artifacts/go-tests')
parser.add_argument('--package', action='append', dest='packages')
args = parser.parse_args()
sys.stdout.reconfigure(errors='backslashreplace')
admin = os.environ['ARTEX_TEST_ADMIN_DSN']
try:
    admin_url = urllib.parse.urlsplit(admin)
    if admin_url.scheme not in ('postgres', 'postgresql') or admin_url.fragment:
        raise ValueError()
    options = urllib.parse.parse_qsl(admin_url.query, keep_blank_values=True, strict_parsing=True)
    if any(key.lower() in ('dbname', 'database', 'service') for key, _ in options):
        raise ValueError()
except ValueError:
    raise SystemExit('Use a PostgreSQL test URL with the database in its path and no service override') from None
output = Path(args.output).resolve()
output.mkdir(parents=True, exist_ok=True)
root = Path(__file__).resolve().parents[1]


def database_sql(statement):
    result = subprocess.run(['psql', '--dbname', admin, '-X', '-v', 'ON_ERROR_STOP=1', '-c', statement],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode:
        operation = statement.split(maxsplit=1)[0]
        raise SystemExit(f'PostgreSQL test database {operation} failed (exit {result.returncode})')


def test_dsn(name):
    return urllib.parse.urlunsplit(admin_url._replace(path='/' + name))


def test_outcome(name, stdout):
    # A test binary can exit successfully even when no test matched the filter.
    records = re.findall(r'^--- (PASS|SKIP|FAIL): ' + re.escape(name) +
                         r' \([^()\n]+\)$', stdout, re.MULTILINE)
    return records[0] if len(records) == 1 else 'FAIL'


packages = subprocess.check_output([
    'go', 'list', '-f', '{{.ImportPath}}|{{.Dir}}|{{len .TestGoFiles}}|{{len .XTestGoFiles}}',
    *(args.packages or ['./...'])], cwd=root, encoding='utf-8').splitlines()
summary = {'passed': [], 'failed': [], 'skipped': [], 'skipped_subtests': []}
with tempfile.TemporaryDirectory(prefix='artex-test-binaries-') as temporary:
    for index, package in enumerate(packages):
        import_path, directory, internal, external = package.split('|')
        if int(internal) + int(external) == 0:
            continue
        binary = Path(temporary) / f'package-{index}.test'
        subprocess.run(['go', 'test', '-c', '-o', str(binary), import_path], cwd=root, check=True)
        # TestMain can initialize the schema before listing any tests. Give
        # discovery its own database so it can never modify a configured one.
        discovery_db = 'artex_test_list_' + uuid.uuid4().hex
        database_sql(f'CREATE DATABASE "{discovery_db}"')
        try:
            discovery_env = dict(os.environ, ARTEX_PG_DSN=test_dsn(discovery_db), NORMA_RIPGREP_NO_INSTALL='1')
            listing = subprocess.check_output([str(binary), '-test.list', '^Test'], cwd=directory,
                                              env=discovery_env, encoding='utf-8', timeout=30)
        finally:
            database_sql(f'DROP DATABASE "{discovery_db}" WITH (FORCE)')
        tests = [name for name in listing.splitlines() if re.fullmatch(r'Test\w+', name)]
        for name in tests:
            database = 'artex_test_' + uuid.uuid4().hex
            database_sql(f'CREATE DATABASE "{database}"')
            env = dict(os.environ, ARTEX_PG_DSN=test_dsn(database), NORMA_RIPGREP_NO_INSTALL='1')
            key = import_path.rsplit('/', 1)[-1] + '-' + name
            label = import_path + '/' + name
            try:
                result = subprocess.run([str(binary), '-test.v', '-test.timeout=90s',
                                         '-test.run', '^' + re.escape(name) + '$'],
                                        cwd=directory, env=env, capture_output=True,
                                        encoding='utf-8', errors='backslashreplace', timeout=100)
                log = result.stdout + result.stderr
                (output / (key + '.log')).write_text(log, encoding='utf-8')
                db_skipped = any(reason in log.lower() for reason in (
                    'postgres unavailable', 'no database config', 'requires isolated artex_pg_dsn'))
                outcome = test_outcome(name, result.stdout)
                summary['skipped_subtests'].extend(
                    line for line in result.stdout.splitlines()
                    if line.lstrip().startswith('--- SKIP: ' + name + '/'))
                if result.returncode or db_skipped or outcome == 'FAIL':
                    summary['failed'].append(label)
                    print('FAIL', label, flush=True)
                    print(log[-12000:], flush=True)
                elif outcome == 'SKIP':
                    summary['skipped'].append(label)
                    print('SKIP', label, flush=True)
                else:
                    summary['passed'].append(label)
                    print('PASS', label, flush=True)
            except subprocess.TimeoutExpired:
                summary['failed'].append(label)
                print('FAIL (timeout)', label, flush=True)
            finally:
                database_sql(f'DROP DATABASE "{database}" WITH (FORCE)')
(output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
print(f'{len(summary["passed"])} passed; {len(summary["failed"])} failed; '
      f'{len(summary["skipped"])} skipped tests; {len(summary["skipped_subtests"])} skipped subtests', flush=True)
raise SystemExit(1 if summary['failed'] else 0)
