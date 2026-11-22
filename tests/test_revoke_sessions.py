import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit
import uuid


ROOT = Path(__file__).resolve().parents[1]
ADMIN = os.environ.get("ARTEX_TEST_ADMIN_DSN")
BASH = os.environ.get("MANDATE_TEST_BASH", "bash")


def psql(dsn, statement):
    result = subprocess.run(
        ["psql", "--dbname", dsn, "-X", "-v", "ON_ERROR_STOP=1", "-Atq", "-c", statement],
        capture_output=True, text=True, timeout=20,
    )
    if result.returncode:
        raise AssertionError("PostgreSQL fixture command failed")
    return result.stdout.strip()


@unittest.skipUnless(ADMIN and shutil.which("psql") and shutil.which(BASH), "requires a disposable PostgreSQL test cluster and Bash")
class SessionRevocationTest(unittest.TestCase):
    def test_revoke_all_without_replacing_password(self):
        admin = urlsplit(ADMIN)
        if admin.scheme not in ("postgres", "postgresql") or admin.fragment or any(
            key.lower() in ("dbname", "database", "service") for key, _ in parse_qsl(admin.query)
        ):
            self.fail("use a PostgreSQL fixture URL with the database in its path")
        name = "mandate_revoke_" + uuid.uuid4().hex
        psql(ADMIN, f'CREATE DATABASE "{name}"')
        self.addCleanup(psql, ADMIN, f'DROP DATABASE "{name}" WITH (FORCE)')
        dsn = urlunsplit(admin._replace(path="/" + name))
        psql(dsn, "CREATE TABLE settings (key text PRIMARY KEY, value text NOT NULL, updated_at timestamptz DEFAULT now())")
        command = [BASH, "reset-password.sh", "-m", "local", "--revoke-sessions", "--yes"]
        env = dict(os.environ, ARTEX_PG_DSN=dsn)

        def revoke(*options, environment=env):
            return subprocess.run(command + list(options), cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True, timeout=20)

        self.assertNotEqual(revoke().returncode, 0)
        self.assertEqual(psql(dsn, "SELECT count(*) FROM settings"), "0")
        psql(dsn, "INSERT INTO settings(key,value) VALUES ('auth.password_hash','fixture-hash'), ('auth.session_generation','old-generation')")
        for options in (("--password-stdin",), ("--new-password", "")):
            conflict = revoke(*options)
            self.assertNotEqual(conflict.returncode, 0)
            self.assertIn("cannot be combined", conflict.stderr)
        generation_query = "SELECT value FROM settings WHERE key='auth.session_generation'"
        self.assertEqual(psql(dsn, generation_query), "old-generation")
        for _ in range(2):
            before = psql(dsn, generation_query)
            result = revoke()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("console sessions revoked", result.stdout)
            self.assertNotEqual(psql(dsn, generation_query), before)

        with tempfile.TemporaryDirectory() as directory:
            service_file = Path(directory) / "pg_service.conf"
            fields = {"host": admin.hostname, "port": admin.port or 5432, "dbname": name,
                      "user": unquote(admin.username or ""), "sslmode": "disable"}
            if admin.password is not None:
                fields["password"] = unquote(admin.password)
            service_file.write_text("[mandate-admin-test]\n" + "".join(f"{key}={value}\n" for key, value in fields.items()),
                                    encoding="utf-8")
            service_env = dict(env, PGSERVICEFILE=str(service_file), ARTEX_PG_DSN="postgres://fixture@127.0.0.1:1/unused")
            before = psql(dsn, generation_query)
            result = revoke("--service", "mandate-admin-test", environment=service_env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PostgreSQL service mandate-admin-test", result.stderr)
            self.assertNotEqual(psql(dsn, generation_query), before)
        self.assertEqual(psql(dsn, "SELECT value FROM settings WHERE key='auth.password_hash'"), "fixture-hash")
