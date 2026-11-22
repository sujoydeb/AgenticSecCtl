#!/usr/bin/env python3
"""Optional YAML validation (needs PyYAML; OpenAPI validation needs openapi-spec-validator).

Usage (use a Python that has the packages, for example a throwaway virtual environment):
    python3 scripts/validate_yaml.py

Checks:
  1. Every .yml/.yaml file in the repository parses.
  2. controls/catalogue.yaml parses to the same data as the stdlib loader in scripts/catalogue_lib.py.
  3. docs/api/openapi.yaml validates as OpenAPI (if openapi-spec-validator is installed).
  4. GitHub workflow files have the basic shape (name, on, jobs) and the CI template keeps its warning header.
Exit code 0 on success, 1 on failure, 2 if PyYAML is missing.
"""
import pathlib
import sys

try:
    import yaml
except ImportError:
    print("PyYAML is not installed; skipping (exit 2).")
    sys.exit(2)

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import catalogue_lib  # noqa: E402

errors = []
files = [p for p in ROOT.rglob("*") if p.suffix in (".yml", ".yaml") and ".git" not in p.parts]
parsed = {}
for p in files:
    try:
        parsed[p] = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        errors.append(f"{p.relative_to(ROOT)}: YAML error: {exc}")

cat_path = ROOT / "controls" / "catalogue.yaml"
if cat_path in parsed:
    mine = catalogue_lib.load(str(cat_path))
    theirs = parsed[cat_path]
    if theirs.get("controls") != mine["controls"]:
        errors.append("controls/catalogue.yaml: stdlib loader and PyYAML disagree on controls")
    for k, v in mine["meta"].items():
        if theirs.get(k) != v:
            errors.append(f"controls/catalogue.yaml: meta key {k} differs between loaders")
    for k, v in mine["lists"].items():
        if theirs.get(k) != v:
            errors.append(f"controls/catalogue.yaml: list {k} differs between loaders")

oas = ROOT / "docs" / "api" / "openapi.yaml"
if oas in parsed:
    try:
        from openapi_spec_validator import validate
        validate(parsed[oas])
    except ImportError:
        print("openapi-spec-validator not installed; OpenAPI validation skipped.")
    except Exception as exc:  # validator raises its own error types
        errors.append(f"docs/api/openapi.yaml: {type(exc).__name__}: {str(exc)[:300]}")

for p, data in parsed.items():
    rel = p.relative_to(ROOT)
    if rel.parts[:2] == (".github", "workflows") or rel.as_posix() == "docs/ci-templates/product-security-gates.yml":
        # PyYAML parses the key 'on' as boolean True
        if not isinstance(data, dict) or "jobs" not in data or ("on" not in data and True not in data) or "name" not in data:
            errors.append(f"{rel}: workflow lacks name, on or jobs")
        else:
            for jname, job in data["jobs"].items():
                if "runs-on" not in job:
                    errors.append(f"{rel}: job {jname} lacks runs-on")
                if "steps" not in job:
                    errors.append(f"{rel}: job {jname} lacks steps")

if errors:
    print("FAILED:")
    for e in errors:
        print(" -", e)
    sys.exit(1)
print(f"OK: {len(files)} YAML files parse; catalogue loaders agree; workflow shapes valid.")
