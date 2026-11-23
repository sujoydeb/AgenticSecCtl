#!/bin/sh
# One command for the local code checks (WP-1.1): boundaries, secrets, unit tests of every package.
set -e
cd "$(dirname "$0")/.."
python3 -I scripts/check_code.py
python3 -I -m unittest discover -s tests/unit -p 'test_*.py'
for p in common api gateway scanner; do
  [ -d services/$p/tests ] || continue
  PYTHONPATH="services/common/src:services/$p/src" python3 -m unittest discover -s services/$p/tests
done
# integration tests: several packages together, PostgreSQL and Docker needed (skipped where Docker is absent)
[ -d tests/integration ] && PYTHONPATH="services/common/src:services/api/src:services/scanner/src" python3 -m unittest discover -s tests/integration
echo "all checks passed"
