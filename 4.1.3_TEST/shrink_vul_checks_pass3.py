#!/usr/bin/env python3
"""
Second‑pass cleaner for V‑checks

• exec_command(...)  ─►  scan_ctx.exec(...).clean
• check.             ─►  stig.
• ctx (stand‑alone)  ─►  scan_ctx
• warns if 'device_name' is still referenced

Input :  cisco_stig_scanner_v4.1.3.AC.1.py
Output:  cisco_stig_scanner_v4.1.3.AC.1.py.pass3
"""

import re
import pathlib
import difflib
import itertools
import sys

SRC  = pathlib.Path("cisco_stig_scanner_v4.1.3.AC.1.py")
DEST = SRC.with_suffix(".pass3")

EXEC_RE      = re.compile(r"exec_command\(\s*([\"'].*?[\"'])\s*,\s*device_name\s*\)")
CHECK_RE     = re.compile(r"\bcheck\.")
CTX_WORD_RE  = re.compile(r"\bctx\b")          # whole‑word ctx
DEV_RE       = re.compile(r"\bdevice_name\b")  # warn if still present

warn_cnt = 0
out_lines = []

for line in SRC.read_text().splitlines(keepends=True):
    # 1) convert exec_command(...)
    line = EXEC_RE.sub(r"scan_ctx.exec(\1).clean", line)

    # 2) replace check. → stig.
    line = CHECK_RE.sub("stig.", line)

    # 3) replace stand‑alone ctx → scan_ctx
    line = CTX_WORD_RE.sub("scan_ctx", line)

    # 4) warning if device_name still lingers
    if DEV_RE.search(line):
        warn_cnt += 1

    out_lines.append(line)

DEST.write_text("".join(out_lines))
print(f"✓ wrote {DEST.name}")
print(f"⚠ {warn_cnt} lines still reference 'device_name' → review manually\n")

# optional preview of first diff hunk
for d in itertools.islice(
        difflib.unified_diff(
            SRC.read_text().splitlines(keepends=True),
            out_lines,
            fromfile=str(SRC),
            tofile=str(DEST),
            n=2), 0, 120):
    sys.stdout.write(d)
