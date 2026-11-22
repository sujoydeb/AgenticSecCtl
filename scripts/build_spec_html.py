#!/usr/bin/env python3
"""Render Plan/functional-spec.md to a self-contained styled HTML file.

Usage: python3 -I scripts/build_spec_html.py Plan/functional-spec.md Plan/functional-spec.html

The markdown is the source of truth. Regenerate the HTML after every spec edit.
Supports only the markdown subset used by the spec: headings, tables, bullet
lists, paragraphs, horizontal rules, `code`, **bold**, *italic*.
"""
import html
import pathlib
import re
import sys


def inline(t):
    t = html.escape(t, quote=False)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", r"<em>\1</em>", t)
    t = re.sub(r"\[VERIFY ([^\]]+)\]", r'<span class="verify" title="\1">VERIFY</span>', t)
    t = t.replace("[VERIFY]", '<span class="verify">VERIFY</span>')
    return t


def cell(t):
    t = t.strip()
    if t in ("M", "S", "C"):
        return f'<span class="pri pri-{t}">{t}</span>'
    if re.fullmatch(r"P[1-5](/P[1-5])?", t):
        return f'<span class="ph">{t}</span>'
    return inline(t)


def render(src_lines):
    body, toc, meta_rows = [], [], []
    title, subtitle, version = "", "", ""
    seen = {}

    def slug(t):
        s = re.sub(r"[^a-z0-9]+", "-", re.sub(r"<[^>]+>", "", t).lower()).strip("-")
        n = seen.get(s, 0)
        seen[s] = n + 1
        return s if n == 0 else f"{s}-{n}"

    i = 0
    while i < len(src_lines):
        ln = src_lines[i]
        if ln.startswith("# "):
            title = ln[2:].strip()
            i += 1
            continue
        if ln.startswith("**") and ln.endswith("**") and ln.count("**") == 2 and not subtitle:
            subtitle = ln.strip("*")
            i += 1
            continue
        if ln.startswith("## "):
            t = ln[3:].strip()
            sid = slug(t)
            toc.append((t, sid))
            body.append(f'<h2 id="{sid}">{inline(t)}</h2>')
            i += 1
            continue
        if ln.startswith("### "):
            t = ln[4:].strip()
            body.append(f'<h3 id="{slug(t)}">{inline(t)}</h3>')
            i += 1
            continue
        if ln.strip() == "---":
            body.append('<hr class="rule">')
            i += 1
            continue
        if ln.startswith("|"):
            rows = []
            while i < len(src_lines) and src_lines[i].startswith("|"):
                rows.append(src_lines[i].strip().strip("|").split("|"))
                i += 1
            hdr = rows[0]
            rest = [r for r in rows[1:] if not all(re.fullmatch(r"\s*:?-+:?\s*", c) for c in r)]
            if all(not c.strip() for c in hdr):  # key/value document-control table
                meta_rows = rest
                for r in rest:
                    if r[0].strip() == "Version":
                        version = r[1].strip().split(" ")[0]
                continue
            h = "".join(f"<th>{inline(c)}</th>" for c in hdr)
            trs = "".join("<tr>" + "".join(f"<td>{cell(c)}</td>" for c in r) + "</tr>" for r in rest)
            body.append(f'<div class="tw"><table><thead><tr>{h}</tr></thead><tbody>{trs}</tbody></table></div>')
            continue
        if re.match(r"^\s*- ", ln):
            items = []
            while i < len(src_lines) and re.match(r"^\s*- ", src_lines[i]):
                items.append(inline(re.sub(r"^\s*- ", "", src_lines[i])))
                i += 1
            body.append("<ul>" + "".join(f"<li>{x}</li>" for x in items) + "</ul>")
            continue
        if not ln.strip():
            i += 1
            continue
        para = [ln]
        i += 1
        while i < len(src_lines) and src_lines[i].strip() and not re.match(r"^(#|\||\s*- |---)", src_lines[i]):
            para.append(src_lines[i])
            i += 1
        txt = " ".join(para)
        callout = txt.startswith(("**Out of scope", "The platform produces", "Targets are proposals", "Test cases are defined"))
        attr = ' class="callout"' if callout else ""
        body.append(f"<p{attr}>{inline(txt)}</p>")
    return title, subtitle, version, meta_rows, toc, body


CSS = """
:root{--bg:#fff;--surface:#f4f6fa;--ink:#16233b;--muted:#5b6780;--navy:#0b1f3a;--blue:#0a5bd3;--line:#dde3ee;
--a1:#ff6a3d;--a2:#e6007e;--warn:#9a5b00;--warnbg:#fff4de;--codebg:#eef2f8}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0d1526;--surface:#15203a;--ink:#e6ebf5;--muted:#9fb0cc;--navy:#e6ebf5;--blue:#6aa5ff;--line:#26355a;--warnbg:#3a2b0a;--warn:#ffcf7a;--codebg:#1b2a4a}}
:root[data-theme="dark"]{--bg:#0d1526;--surface:#15203a;--ink:#e6ebf5;--muted:#9fb0cc;--navy:#e6ebf5;--blue:#6aa5ff;--line:#26355a;--warnbg:#3a2b0a;--warn:#ffcf7a;--codebg:#1b2a4a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 "Helvetica Neue",Arial,system-ui,sans-serif}
.hero{background:linear-gradient(120deg,#0b1f3a 0%,#143a7a 60%,#0a5bd3 100%);color:#fff;padding:56px 16px 48px;position:relative}
.hero::after{content:"";position:absolute;left:0;right:0;bottom:0;height:6px;background:linear-gradient(90deg,var(--a1),var(--a2))}
.wrap{max-width:1180px;margin:0 auto;padding:0 16px}
.brand{font-weight:700;letter-spacing:.14em;font-size:13px;text-transform:uppercase;opacity:.85;margin-bottom:14px}
.hero h1{font-size:clamp(30px,5vw,48px);line-height:1.1;margin:0 0 12px;font-weight:700}
.hero p.sub{font-size:clamp(16px,2vw,20px);margin:0 0 24px;opacity:.9;max-width:760px}
.chips{display:flex;flex-wrap:wrap;gap:10px}
.chip{background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.25);border-radius:999px;padding:6px 14px;font-size:14px}
.chip span{opacity:.7;margin-right:8px;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.layout{display:grid;grid-template-columns:260px minmax(0,1fr);gap:40px;padding-top:32px;padding-bottom:64px}
nav.toc{position:sticky;top:16px;align-self:start;max-height:calc(100vh - 32px);overflow:auto;border-left:3px solid var(--line);padding-left:14px;font-size:14px}
nav.toc a{display:block;color:var(--muted);text-decoration:none;padding:5px 0}
nav.toc a:hover{color:var(--blue)}
nav.toc .lbl{font-size:12px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:6px}
main h2{font-size:28px;color:var(--navy);margin:48px 0 16px;padding-top:18px;position:relative;line-height:1.2}
main h2::before{content:"";position:absolute;top:0;left:0;width:56px;height:4px;background:linear-gradient(90deg,var(--a1),var(--a2));border-radius:2px}
main h3{font-size:20px;color:var(--navy);margin:32px 0 10px}
p{margin:0 0 14px}
ul{padding-left:22px;margin:0 0 16px} li{margin:4px 0}
code{background:var(--codebg);padding:1px 6px;border-radius:4px;font:13px ui-monospace,Menlo,Consolas,monospace}
.callout{background:var(--surface);border-left:4px solid var(--blue);padding:12px 16px;border-radius:0 8px 8px 0}
.tw{overflow-x:auto;margin:0 0 22px;border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:14px;min-width:560px}
th{background:var(--surface);color:var(--navy);text-align:left;font-weight:700;padding:10px 12px;border-bottom:2px solid var(--line);white-space:nowrap}
td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
tbody tr:hover{background:color-mix(in srgb,var(--blue) 5%,transparent)}
.pri,.ph{display:inline-block;min-width:26px;text-align:center;border-radius:999px;padding:1px 9px;font-size:12px;font-weight:700}
.pri-M{background:#fde7ee;color:#b00045} .pri-S{background:#fff0d6;color:#8a5200} .pri-C{background:#e4efff;color:#0a4aa8}
.ph{background:var(--surface);color:var(--navy);border:1px solid var(--line)}
.verify{background:var(--warnbg);color:var(--warn);font-size:11px;font-weight:700;padding:1px 6px;border-radius:4px;letter-spacing:.04em}
hr.rule{border:0;border-top:1px solid var(--line);margin:28px 0}
footer{border-top:1px solid var(--line);color:var(--muted);font-size:13px;padding:20px 16px;text-align:center}
@media (max-width:900px){.layout{grid-template-columns:1fr} nav.toc{position:static;max-height:none;border-left:0;padding-left:0;border-bottom:1px solid var(--line);padding-bottom:12px}}
@media print{nav.toc{display:none} .layout{display:block} .hero{-webkit-print-color-adjust:exact;print-color-adjust:exact} .tw{overflow:visible} table{min-width:0}}
"""


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    src = pathlib.Path(argv[1]).read_text(encoding="utf-8").split("\n")
    title, subtitle, version, meta_rows, toc, body = render(src)
    chips = "".join(
        f'<div class="chip"><span>{inline(r[0])}</span>{inline(r[1])}</div>' for r in meta_rows if len(r) >= 2
    )
    toc_html = "".join(f'<a href="#{s}">{html.escape(t)}</a>' for t, s in toc)
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgenticSecCtl Functional Specification v{html.escape(version)}</title>
<style>{CSS}</style></head>
<body>
<header class="hero"><div class="wrap">
<div class="brand">AgenticSecCtl &middot; Functional Specification</div>
<h1>{html.escape(title)}</h1>
<p class="sub">{html.escape(subtitle)}</p>
<div class="chips">{chips}</div>
</div></header>
<div class="wrap layout">
<nav class="toc" aria-label="Contents"><div class="lbl">Contents</div>{toc_html}</nav>
<main>
{"".join(body)}
</main></div>
<footer>AgenticSecCtl functional specification v{html.escape(version)} &middot; draft for review &middot; generated from functional-spec.md by scripts/build_spec_html.py</footer>
</body></html>"""
    pathlib.Path(argv[2]).write_text(page, encoding="utf-8")
    print(f"wrote {argv[2]} ({len(page)} bytes, version {version})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
