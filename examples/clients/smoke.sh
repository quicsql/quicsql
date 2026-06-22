#!/usr/bin/env bash
# Smoke-run every client-language example against a scratch quicSQL server.
# Each example exits non-zero on any failed assertion, so this doubles as an
# integration test of the wire protocols against real third-party SDKs.
#
#   ./smoke.sh                 # or: just clients-smoke   (from the repo root)
#
# Toolchains are used when present (node, python3, docker) and skipped
# gracefully otherwise. SDKs that ship prebuilt binaries without a
# linux-aarch64 build (python libsql wheel, PHP extension) run under
# linux/amd64 emulation on ARM hosts.

set -u
cd "$(dirname "$0")"

PORT="${QUICSQL_PORT:-7785}"                     # off the canonical 7775 so a dev server can coexist
export QUICSQL_TOKEN="${QUICSQL_TOKEN:-dev-token}"
export QUICSQL_URL="http://127.0.0.1:${PORT}"
DOCKER_URL="http://host.docker.internal:${PORT}" # how a container reaches the host

AMD64=""
case "$(uname -m)" in arm64 | aarch64) AMD64="--platform linux/amd64" ;; esac

rm -rf data && mkdir -p data
sed "s/0.0.0.0:7775/0.0.0.0:${PORT}/" server.yaml > data/server.smoke.yaml
go run ../../cmd/quicsql --config data/server.smoke.yaml >data/server.log 2>&1 &
SERVER_PID=$!
trap 'kill "${SERVER_PID}" 2>/dev/null' EXIT

for _ in $(seq 1 50); do
  curl -so /dev/null "http://127.0.0.1:${PORT}/_health" && break
  sleep 0.2
done
curl -so /dev/null "http://127.0.0.1:${PORT}/_health" || { echo "server did not come up; see data/server.log"; exit 1; }

FAILED=0
RESULTS=()
run() { # run <name> <command...>
  local name=$1
  shift
  echo "──── ${name}"
  if "$@"; then RESULTS+=("PASS ${name}"); else
    RESULTS+=("FAIL ${name}")
    FAILED=1
  fi
}
skip() { RESULTS+=("SKIP $1 ($2)"); }

# ── Node ────────────────────────────────────────────────────────────────────
if command -v node >/dev/null; then
  run node-fetch node node-fetch/main.mjs
  run node-libsql bash -c 'cd node-libsql && npm install --no-fund --no-audit --silent && node main.ts'
  run node-drizzle bash -c 'cd node-drizzle && npm install --no-fund --no-audit --silent && node main.ts'
else
  skip node-fetch "node not installed" && skip node-libsql "node not installed" && skip node-drizzle "node not installed"
fi

# ── Python ──────────────────────────────────────────────────────────────────
# The SDK examples need prebuilt wheels (libsql ships none for linux-aarch64 or
# CPython 3.14 on macOS). Try a native venv with --only-binary to fail fast,
# fall back to an amd64 Python container.
py_native_or_docker() { # <dir>
  local dir=$1
  if python3 -m venv "${dir}/.venv" 2>/dev/null \
    && "${dir}/.venv/bin/pip" install --quiet --only-binary=:all: -r "${dir}/requirements.txt" 2>/dev/null; then
    "${dir}/.venv/bin/python" "${dir}/main.py"
  elif command -v docker >/dev/null; then
    echo "(no native wheel for this Python — running in a python:3.12-slim container)"
    docker run --rm ${AMD64} -v "${PWD}/${dir}:/app" -w /app \
      -e QUICSQL_URL="${DOCKER_URL}" -e QUICSQL_TOKEN="${QUICSQL_TOKEN}" \
      python:3.12-slim sh -c 'pip install -q -r requirements.txt && python main.py'
  else
    echo "no compatible wheel and no docker"
    return 1
  fi
}
if command -v python3 >/dev/null; then
  run python-stdlib python3 python-stdlib/main.py
  run python-libsql py_native_or_docker python-libsql
  run python-sqlalchemy py_native_or_docker python-sqlalchemy
else
  skip python-stdlib "python3 not installed" && skip python-libsql "python3 not installed" && skip python-sqlalchemy "python3 not installed"
fi

# ── PHP (via Docker; use a local php for php-curl when present) ─────────────
if command -v php >/dev/null; then
  run php-curl php php-curl/main.php
elif command -v docker >/dev/null; then
  run php-curl docker run --rm -v "${PWD}/php-curl:/app" -w /app \
    -e QUICSQL_URL="${DOCKER_URL}" -e QUICSQL_TOKEN="${QUICSQL_TOKEN}" \
    php:8.3-cli php main.php
else
  skip php-curl "neither php nor docker installed"
fi
if command -v docker >/dev/null; then
  run php-libsql bash -c "docker build ${AMD64} -q -t quicsql-php-libsql php-libsql/ >/dev/null \
    && docker run --rm ${AMD64} -e QUICSQL_URL='${DOCKER_URL}' -e QUICSQL_TOKEN='${QUICSQL_TOKEN}' quicsql-php-libsql"
else
  skip php-libsql "docker not installed"
fi

echo
echo "════ client examples ════"
printf '%s\n' "${RESULTS[@]}"
exit "${FAILED}"
