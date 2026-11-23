#!/usr/bin/env python3
"""Code baseline checks (WP-1.1): import boundaries, HTTP-client ban, secret scan.

Stdlib only. Usage: python3 -I scripts/check_code.py [--root DIR]
Exit 0 when clean, 1 on any violation.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

PLANES = {"gateway": {"api", "scanner"}, "api": {"gateway"}, "scanner": {"gateway"}}
# Only the guarded wrapper in common may import an HTTP client (WP-1.3).
HTTP_CLIENTS = {"requests", "httpx", "urllib3", "aiohttp", "http.client", "urllib.request", "pycurl"}
HTTP_ALLOWED = ("services/common/src/agenticsecctl_common/http",)
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
]
SECRET_SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules"}
SECRET_SKIP_FILES = {"scripts/check_code.py"}  # holds the patterns themselves
SECRET_EXTS = {".py", ".md", ".yaml", ".yml", ".json", ".toml", ".env", ".sh", ".rego", ".sql", ".ts", ".tsx", ".txt", ""}


def _imports(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            yield node.module


def check_imports(root: Path) -> list[str]:
    errs: list[str] = []
    for f in sorted((root / "services").glob("*/src/**/*.py")):
        rel = f.relative_to(root).as_posix()
        pkg = rel.split("/")[1]
        try:
            tree = ast.parse(f.read_text(encoding="utf-8"), filename=rel)
        except SyntaxError as e:
            errs.append(f"{rel}: syntax error: {e.msg}")
            continue
        for mod in _imports(tree):
            top = mod.split(".")[0]
            for other in PLANES.get(pkg, ()):
                if top == f"agenticsecctl_{other}":
                    errs.append(f"{rel}: {pkg} must not import {other} (use common)")
            if not rel.startswith(HTTP_ALLOWED) and any(
                    mod == c or mod.startswith(c + ".") for c in HTTP_CLIENTS):
                errs.append(f"{rel}: HTTP client '{mod}' only allowed in the guarded wrapper")
    return errs


def check_secrets(root: Path) -> list[str]:
    errs: list[str] = []
    for f in sorted(root.rglob("*")):
        if not f.is_file() or SECRET_SKIP_DIRS & set(f.relative_to(root).parts):
            continue
        rel = f.relative_to(root).as_posix()
        if rel in SECRET_SKIP_FILES or f.suffix not in SECRET_EXTS:
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for p in SECRET_PATTERNS:
            if p.search(text):
                errs.append(f"{rel}: matches secret pattern {p.pattern[:30]}...")
                break
    return errs


def main(argv: list[str]) -> int:
    root = Path(argv[argv.index("--root") + 1]) if "--root" in argv else Path(__file__).resolve().parent.parent
    errs = check_imports(root) + check_secrets(root)
    for e in errs:
        print("FAIL", e)
    print("code checks:", "FAILED" if errs else "ok")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
