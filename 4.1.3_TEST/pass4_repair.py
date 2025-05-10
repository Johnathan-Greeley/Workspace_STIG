#!/usr/bin/env python3
"""
pass4_repair.py – undo illegal 'res.clean' replacements introduced by the
previous auto-pass, and restore the original handle_errors signatures.
Run once after shrink_vul_checks_pass4.py.
"""
import re, pathlib, difflib, itertools, sys

SRC  = pathlib.Path("cisco_stig_scanner_v4.1.3.AC.2.pass4.py")
DEST = SRC.with_suffix(".fixed.py")

code = SRC.read_text().splitlines(keepends=True)
out  = []

# regexes
RES_DOT_EQ   = re.compile(r'^\s*res\.clean\s*=')
SIG_BROKEN   = re.compile(r'def\s+(\w+)\s*\(\s*res\.clean\s*,')
DOC_MANGLE   = re.compile(r'vulnerability res\.clean')

for line in code:
    # 1. fix assignments like "res.clean ="
    if RES_DOT_EQ.match(line):
        out.append(line.replace('res.clean', 'result', 1))
        continue

    # 2. restore broken function signatures
    if SIG_BROKEN.search(line):
        line = line.replace('res.clean', 'result', 1)

    # 3. undo doc-string text damage
    line = DOC_MANGLE.sub('vulnerability result', line)

    out.append(line)

# write file
DEST.write_text(''.join(out))
print(f"✓ wrote {DEST.name}")

# quick diff preview
for d in itertools.islice(
        difflib.unified_diff(code, out, fromfile=str(SRC), tofile=str(DEST), n=1),
        0, 120):
    sys.stdout.write(d)
