#!/bin/sh
# Runs the P0-19 spike in a throwaway PostgreSQL container. Needs Docker.
# Usage: db/spike/run.sh   (from anywhere)
set -eu
set -o pipefail 2>/dev/null || true
here=$(cd "$(dirname "$0")" && pwd)
name=agenticsecctl-pg-spike
image=postgres:17-alpine
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" -e POSTGRES_PASSWORD=spike -v "$here":/spike:ro "$image" >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
i=0
until docker exec "$name" pg_isready -U postgres -q 2>/dev/null && docker exec "$name" psql -U postgres -qtAc 'select 1' >/dev/null 2>&1; do
  i=$((i+1)); [ "$i" -gt 60 ] && { echo "postgres did not start"; exit 1; }; sleep 1
done
psqlx() { docker exec "$name" psql -U postgres -v ON_ERROR_STOP=1 -q "$@"; }
docker exec "$name" psql -U postgres -qc 'CREATE DATABASE spike'
docker exec "$name" psql -U postgres -tAc 'select version()' | head -1
echo "== migration up, down, up on an empty database"
psqlx -d spike -f /spike/0001_core.up.sql
before=$(psqlx -d spike -tAc "select count(*) from pg_class where relnamespace = 'public'::regnamespace")
psqlx -d spike -f /spike/0001_core.down.sql
empty=$(psqlx -d spike -tAc "select count(*) from pg_class where relnamespace = 'public'::regnamespace")
psqlx -d spike -f /spike/0001_core.up.sql
after=$(psqlx -d spike -tAc "select count(*) from pg_class where relnamespace = 'public'::regnamespace")
echo "relations in public: after up $before, after down $empty, after up again $after"
[ "$empty" = 0 ] && [ "$before" = "$after" ] || { echo "FAIL migration up/down"; exit 1; }
echo "PASS migration up, down and up again"
echo "== tests"
psqlx -d spike -o /dev/null -f /spike/rls_tests.sql 2>&1 | sed -e 's/^psql:[^ ]* NOTICE:  //'
