#!/usr/bin/env python3
"""Generate controls/catalogue.md from controls/catalogue.yaml.

Usage: python3 -I scripts/build_catalogue_md.py controls/catalogue.yaml controls/catalogue.md
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import catalogue_lib  # noqa: E402


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    cat = catalogue_lib.load(argv[1])
    problems = catalogue_lib.validate_structure(cat)
    if problems:
        print("Catalogue structure problems:")
        for p in problems:
            print(" -", p)
        return 1
    pathlib.Path(argv[2]).write_text(catalogue_lib.render_markdown(cat), encoding="utf-8")
    print(f"wrote {argv[2]} ({len(cat['controls'])} controls)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
