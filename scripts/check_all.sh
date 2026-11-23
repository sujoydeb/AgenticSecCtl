#!/bin/sh
# One command for the local code checks (WP-1.1): boundaries, secrets, unit tests of every package.
set -e
cd "$(dirname "$0")/.."
python3 -I scripts/check_code.py
# lint and strict type check (ruff and mypy come from services/api/requirements-dev.lock)
for tool in ruff mypy; do
  python3 -m "$tool" --version >/dev/null 2>&1 || { echo "$tool is not installed: pip install --require-hashes -r services/api/requirements-dev.lock -r services/api/requirements-binary.lock"; exit 1; }
done
python3 -m ruff check .
python3 -m mypy services/common/src services/api/src services/scanner/src
python3 -I -m unittest discover -s tests/unit -p 'test_*.py'
for p in common api gateway scanner; do
  [ -d services/$p/tests ] || continue
  PYTHONPATH="services/common/src:services/$p/src" python3 -m unittest discover -s services/$p/tests
done
# integration tests: several packages together, PostgreSQL and Docker needed (skipped where Docker is absent)
for d in tests/integration tests/e2e; do
  [ -d "$d" ] && PYTHONPATH="services/common/src:services/api/src:services/scanner/src" python3 -m unittest discover -s "$d"
done
echo "all checks passed"
