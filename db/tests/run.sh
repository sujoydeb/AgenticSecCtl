#!/usr/bin/env bash
# WP-1.5: runs migrations up, down, up and the schema tests in a throwaway PostgreSQL container. Needs Docker.
# Usage: db/tests/run.sh   (from anywhere); PG_IMAGE overrides the image. Exits non-zero on any failure.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
mig=$(cd "$here/../migrations" && pwd)
name=agenticsecctl-pg-schema
image=${PG_IMAGE:-postgres:17-alpine}
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" -e POSTGRES_PASSWORD=test -v "$mig":/mig:ro -v "$here":/tests:ro "$image" >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
i=0
until docker exec "$name" pg_isready -U postgres -q 2>/dev/null && docker exec "$name" psql -U postgres -qtAc 'select 1' >/dev/null 2>&1; do
  i=$((i+1)); [ "$i" -gt 60 ] && { echo "postgres did not start"; exit 1; }; sleep 1
done
psqlx() { docker exec "$name" psql -U postgres -v ON_ERROR_STOP=1 -q "$@"; }
docker exec "$name" psql -U postgres -qc 'CREATE DATABASE schema_test'
docker exec "$name" psql -U postgres -tAc 'select version()' | head -1
count() { psqlx -d schema_test -tAc "select count(*) from pg_class where relnamespace = 'public'::regnamespace"; }
echo "== migrations up, down, up on an empty database"
for f in $(ls "$mig"/*.up.sql | sort); do psqlx -d schema_test -f "/mig/$(basename "$f")"; done
before=$(count)
for f in $(ls "$mig"/*.down.sql | sort -r); do psqlx -d schema_test -f "/mig/$(basename "$f")"; done
empty=$(count)
for f in $(ls "$mig"/*.up.sql | sort); do psqlx -d schema_test -f "/mig/$(basename "$f")"; done
after=$(count)
echo "relations in public: after up $before, after down $empty, after up again $after"
[ "$empty" = 0 ] && [ "$before" = "$after" ] || { echo "FAIL migration up/down"; exit 1; }
echo "PASS migrations up, down and up again"
echo "== schema tests"
psqlx -d schema_test -o /dev/null -f /tests/schema_tests.sql 2>&1 | sed -e 's/^psql:[^ ]* NOTICE:  //'
