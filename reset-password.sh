#!/usr/bin/env bash
# =============================================================================
# ARTEX administrator password reset script
#
# The login username is always ARTEX; the password is stored as a bcrypt hash
# under the auth.password_hash key in the settings table. This script connects,
# generates a bcrypt hash in-database with pgcrypto, and writes it back—fully
# compatible with backend login verification (golang.org/x/crypto/bcrypt).
#
# Deployments:
#   local  (default) — psql on the host. Priority: command-line args >
#                      --dsn/$ARTEX_PG_DSN > config.json database.*
#   docker         — psql inside the postgres container via `docker compose
#                    exec` (or `docker exec`); 5432 is not exposed on the host.
#
# Usage:
#   ./reset-password.sh                          # local, prompt for a new password
#   ./reset-password.sh --password-stdin -y < /private/path/password
#   ./reset-password.sh --dsn postgres://u@h:5432/artex
#   ./reset-password.sh --service mandate-admin   # reads libpq service settings
#   ./reset-password.sh -H 127.0.0.1 -P 5433 -U autopentest -d artex
#   ./reset-password.sh -m docker                # docker (uses the running database container settings)
#   ./reset-password.sh -m docker -c pg --exec docker
#   ./reset-password.sh -m docker --revoke-sessions  # revoke sessions only
# For automation, --password-stdin reads one line and preserves spaces.
# Keep secrets out of -p, -W, and connection strings passed to psql.
# =============================================================================
set +ax
set -euo pipefail
unset NEWPASS NEWPASS2 ARTEX_RESET_NEWPASS

PASS_KEY="auth.password_hash"
BCRYPT_COST=10

MODE=""            # local | docker (empty = auto-detect)
DSN=""
SERVICE=""
HOST="" PORT="" USER="" DBPASS="" DBNAME="" SSLMODE=""
CONFIG=""
CONTAINER=""       # postgres service/container name in docker mode (default: postgres)
EXEC_KIND=""       # compose | docker (which exec to use in docker mode; empty = auto)
NEWPASS=""
PASSWORD_STDIN=0
PASSWORD_ARG=0
REVOKE_SESSIONS=0
ASSUME_YES=0

die() { echo "Error: $*" >&2; exit 1; }
info() { echo "· $*" >&2; }

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

# ---- Argument parsing ------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--mode)        MODE="${2:-}"; [[ "$MODE" == local || "$MODE" == docker ]] || die "--mode requires local or docker"; shift 2 ;;
    --dsn)            DSN="${2:-}"; shift 2 ;;
    --service)        SERVICE="${2:-}"; [[ -n "$SERVICE" ]] || die "--service requires a PostgreSQL service name"; shift 2 ;;
    -H|--host)        HOST="${2:-}"; shift 2 ;;
    -P|--port)        PORT="${2:-}"; shift 2 ;;
    -U|--user)        USER="${2:-}"; shift 2 ;;
    -W|--db-password) DBPASS="${2:-}"; shift 2 ;;
    -d|--dbname)      DBNAME="${2:-}"; shift 2 ;;
    --sslmode)        SSLMODE="${2:-}"; shift 2 ;;
    --config)         CONFIG="${2:-}"; [[ -n "$CONFIG" ]] || die "--config requires a path"; shift 2 ;;
    -c|--container)   CONTAINER="${2:-}"; shift 2 ;;
    --exec)           EXEC_KIND="${2:-}"; [[ "$EXEC_KIND" == compose || "$EXEC_KIND" == docker ]] || die "--exec requires compose or docker"; shift 2 ;;
    --password-stdin) PASSWORD_STDIN=1; shift ;;
    --revoke-sessions) REVOKE_SESSIONS=1; shift ;;
    -p|--new-password) NEWPASS="${2:-}"; PASSWORD_ARG=1; shift 2 ;;
    -y|--yes)         ASSUME_YES=1; shift ;;
    -h|--help)        usage ;;
    *) die "unknown argument: $1 (use -h for usage)" ;;
  esac
done

if [[ "$REVOKE_SESSIONS" == 1 && ( "$PASSWORD_STDIN" == 1 || "$PASSWORD_ARG" == 1 ) ]]; then
  die "--revoke-sessions cannot be combined with new password inputs"
fi
if [[ -n "$SERVICE" && -n "$DSN$HOST$PORT$USER$DBPASS$DBNAME$SSLMODE$CONFIG" ]]; then
  die "--service cannot be combined with other database connection options"
fi

# ---- Read database.* from config.json (local mode only, when no connection is given explicitly) -----
read_config_json() {
  python3 - "$1" <<'PY'
import json
import os
import stat
import sys

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result

try:
    limit = 1 << 20  # Same config.json limit as the server.
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(sys.argv[1], flags), "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError()
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ValueError()
    db = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)["database"]
    if not isinstance(db, dict):
        raise ValueError()
    fields = []
    for key in ("dsn", "host", "port", "user", "password", "dbname", "sslmode"):
        value = db.get(key)
        if value is None:
            continue
        if key == "port" and type(value) is int:
            value = str(value)
        if not isinstance(value, str) or "\0" in value:
            raise ValueError()
        fields.extend((key.encode("ascii"), value.encode("utf-8")))
    sys.stdout.buffer.write(b"\0".join(fields + [b"end", b""]))
except (OSError, ValueError, KeyError, TypeError, RecursionError):
    sys.exit("Invalid database configuration")
PY
}

apply_config_fields() {
  local key val
  while IFS= read -r -d '' key; do
    [[ "$key" != end ]] || return 0
    IFS= read -r -d '' val || return 1
    case "$key" in
      dsn)      DSN="$val" ;;
      host)     HOST="$val" ;;
      port)     [[ -n "$PORT" ]] || PORT="$val" ;;
      user)     USER="$val" ;;
      password) [[ -n "$DBPASS" ]] || DBPASS="$val" ;;
      dbname)   DBNAME="$val" ;;
      sslmode)  [[ -n "$SSLMODE" ]] || SSLMODE="$val" ;;
    esac
  done
  return 1
}

compose=(docker compose)
if [[ -f docker-compose.safe.yml ]]; then
  compose+=(--env-file .env.safe -f docker-compose.safe.yml)
fi

# ---- Auto-detect mode ------------------------------------------------------
if [[ -n "$CONFIG" && -n "$DSN$HOST$USER$DBNAME" ]]; then
  die "--config conflicts with explicit database connection options"
fi
if [[ -z "$MODE" ]]; then
  if [[ -n "$EXEC_KIND$CONTAINER" ]]; then
    MODE="docker"
  elif [[ -n "$SERVICE$DSN$HOST$USER$DBNAME$CONFIG" || -n "${ARTEX_PG_DSN:-}${ARTEX_CONFIG:-}" || -f config.json ]]; then
    MODE="local"
  elif command -v docker >/dev/null 2>&1 && [[ -f docker-compose.safe.yml || -f docker-compose.yml ]]; then
    MODE="docker"
  else
    MODE="local"
  fi
fi
if [[ "$MODE" == docker && -n "$SERVICE$DSN$HOST$PORT$SSLMODE$CONFIG" ]]; then
  die "Docker recovery cannot apply local connection options"
fi
if [[ "$MODE" == local && -n "$EXEC_KIND$CONTAINER" ]]; then
  die "Local recovery cannot apply container options"
fi
info "Deployment mode: $MODE"

# ---- Prepare the selected recovery action ----------------------------------
if [[ "$REVOKE_SESSIONS" == 1 ]]; then
  ACTION="Revoke all Mandate console sessions"
  SQL=$(cat <<'SQL'
\set ON_ERROR_STOP on
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM settings WHERE key = 'auth.password_hash' AND value <> '') THEN
    RAISE EXCEPTION 'Administrator setup is incomplete';
  END IF;
  INSERT INTO settings(key, value)
  VALUES ('auth.session_generation', gen_random_uuid()::text)
  ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();
END
$$;
SQL
)
else
  ACTION="Reset the Mandate administrator password"
  if [[ "$PASSWORD_STDIN" == 1 ]]; then
    [[ -z "$NEWPASS" ]] || die "choose one new password input"
    IFS= read -r -s NEWPASS || [[ -n "$NEWPASS" ]] || die "missing password on standard input"
  elif [[ -z "$NEWPASS" ]]; then
    IFS= read -r -s -p "Enter new password (username is always ARTEX): " NEWPASS; echo >&2
    [[ -n "$NEWPASS" ]] || die "password cannot be empty"
    IFS= read -r -s -p "Enter again to confirm: " NEWPASS2; echo >&2
    [[ "$NEWPASS" == "$NEWPASS2" ]] || die "the two entries do not match"
  fi
  [[ -n "$NEWPASS" ]] || die "password cannot be empty"
  unset NEWPASS2

  # psql quotes the password value. The database role needs access to pgcrypto.
  SQL=$(cat <<SQL
\\set ON_ERROR_STOP on
\\getenv newpw ARTEX_RESET_NEWPASS
SELECT char_length(:'newpw') >= 8 AND octet_length(convert_to(:'newpw', 'UTF8')) <= 72 AS password_valid
\\gset
\\if :password_valid
\\else
DO 'BEGIN RAISE EXCEPTION ''Password requires at least 8 characters and at most 72 UTF-8 bytes''; END';
\\endif
CREATE EXTENSION IF NOT EXISTS pgcrypto;
INSERT INTO settings(key, value)
VALUES ('$PASS_KEY', crypt(:'newpw', gen_salt('bf', $BCRYPT_COST))),
       ('auth.session_generation', encode(gen_random_bytes(32), 'hex'))
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();
SQL
  )
fi

# ---- Execute ---------------------------------------------------------------
# Let explicit DSN or service settings override libpq's environment default.
export PGCONNECT_TIMEOUT="${PGCONNECT_TIMEOUT:-10}"
if [[ "$MODE" == "local" ]]; then
  # Connection priority: command line > --dsn/$ARTEX_PG_DSN > config.json
  if [[ -z "$SERVICE$CONFIG$DSN$HOST$USER$DBNAME" ]]; then
    [[ -n "${ARTEX_PG_DSN:-}" ]] && DSN="$ARTEX_PG_DSN"
  fi
  if [[ -z "$SERVICE$DSN" && -z "$HOST$USER$DBNAME" ]]; then
    cfg="${CONFIG:-${ARTEX_CONFIG:-config.json}}"
    if [[ -n "$CONFIG${ARTEX_CONFIG:-}" && ! -f "$cfg" ]]; then
      die "selected database configuration must be an existing regular file"
    fi
    if [[ -f "$cfg" ]]; then
      info "Reading database configuration from $cfg"
      command -v python3 >/dev/null 2>&1 || die "reading config.json requires Python 3"
      apply_config_fields < <(read_config_json "$cfg") || die "Could not read database configuration"
    fi
  fi

  command -v psql >/dev/null 2>&1 || die "psql not found on this machine (install postgresql-client, or use -m docker)"

  declare -a PSQL_ARGS=()
  if [[ -n "$SERVICE" ]]; then
    export PGSERVICE="$SERVICE"
    printf -v target 'PostgreSQL service %q' "$SERVICE"
  elif [[ -n "$DSN" ]]; then
    PSQL_ARGS=(--dbname="$DSN")
    target="configured PostgreSQL connection (credentials hidden)"
  else
    [[ -n "$USER"   ]] || die "missing database user (-U) or a valid config.json/DSN"
    [[ -n "$DBNAME" ]] || die "missing database name (-d) or a valid config.json/DSN"
    HOST="${HOST:-127.0.0.1}"; PORT="${PORT:-5432}"; SSLMODE="${SSLMODE:-disable}"
    # psql interprets a -d value containing "=" as connection settings.
    # PGDATABASE supplies the literal database name as a libpq default.
    export PGDATABASE="$DBNAME"
    PSQL_ARGS=(-h "$HOST" -p "$PORT" -U "$USER")
    [[ -n "$SSLMODE" ]] && export PGSSLMODE="$SSLMODE"
    [[ -n "$DBPASS" ]] && export PGPASSWORD="$DBPASS"
    printf -v target '%q@%q:%q/%q' "$USER" "$HOST" "$PORT" "$DBNAME"
  fi

  info "Target database: $target"
  if [[ "$ASSUME_YES" -ne 1 ]]; then
    read -r -p "$ACTION in this database? [y/N] " ans
    [[ "$ans" == "y" || "$ans" == "Y" ]] || die "cancelled"
  else
    PSQL_ARGS+=(-w)
  fi

  if ! printf '%s\n' "$SQL" | ARTEX_RESET_NEWPASS="$NEWPASS" psql -X "${PSQL_ARGS[@]}" -v ON_ERROR_STOP=1 -q >/dev/null; then
    if [[ "$REVOKE_SESSIONS" == 1 ]]; then
      die "Session revocation failed. Check the database target and administrator setup."
    fi
    die "Write failed. If pgcrypto permissions/availability is reported, use a role with extension-creation privileges, or run CREATE EXTENSION pgcrypto manually first."
  fi

else
  # ---- docker ----
  command -v docker >/dev/null 2>&1 || die "docker not found"
  CONTAINER="${CONTAINER:-postgres}"

  # Choose the exec method: prefer docker compose exec (service name), otherwise docker exec (container name)
  if [[ -z "$EXEC_KIND" ]]; then
    if docker compose version >/dev/null 2>&1 && [[ -f docker-compose.safe.yml || -f docker-compose.yml ]]; then
      EXEC_KIND="compose"
    else
      EXEC_KIND="docker"
    fi
  fi

  # The container already has its database settings. Never source a checkout's .env.
  export PGUSER="${USER:-${POSTGRES_USER:-}}"
  export PGDATABASE="${DBNAME:-${POSTGRES_DB:-}}"
  export PGPASSWORD="${DBPASS:-${PGPASSWORD:-${POSTGRES_PASSWORD:-}}}"

  info "Target: database ${PGDATABASE:-from container settings} in $CONTAINER (exec=$EXEC_KIND)"
  if [[ "$ASSUME_YES" -ne 1 ]]; then
    read -r -p "$ACTION in this container's database? [y/N] " ans
    [[ "$ans" == "y" || "$ans" == "Y" ]] || die "cancelled"
  fi

  # -e passes only the name, not the value → inherited from the current environment, so the password never appears in the docker command argv.
  if [[ "$EXEC_KIND" == "compose" ]]; then
    EXEC_CMD=("${compose[@]}" exec -T)
  else
    EXEC_CMD=(docker exec -i)
  fi
  EXEC_CMD+=(-e ARTEX_RESET_NEWPASS -e PGPASSWORD -e PGUSER -e PGDATABASE -e PGCONNECT_TIMEOUT "$CONTAINER" sh -c '
    export PGUSER="${PGUSER:-${POSTGRES_USER:-artex}}"
    export PGDATABASE="${PGDATABASE:-${POSTGRES_DB:-artex}}"
    export PGPASSWORD="${PGPASSWORD:-${POSTGRES_PASSWORD:-}}"
    exec psql -X -w -v ON_ERROR_STOP=1 -q
  ')

  if ! printf '%s\n' "$SQL" | ARTEX_RESET_NEWPASS="$NEWPASS" "${EXEC_CMD[@]}" >/dev/null; then
    if [[ "$REVOKE_SESSIONS" == 1 ]]; then
      die "Session revocation failed. Check the container database target and administrator setup."
    fi
    die "Write failed. Check the container name (-c), the container database settings, and that the role has pgcrypto privileges."
  fi
fi

unset NEWPASS
if [[ "$REVOKE_SESSIONS" == 1 ]]; then
  echo "All Mandate console sessions revoked. Sign in again with the existing administrator password."
  exit 0
fi
echo "✓ ARTEX administrator password reset. Log in with username ARTEX and the new password (no service restart required)."
