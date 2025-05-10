#!/usr/bin/env python3
"""
Batch‑edit the big STIG scanner file:

  • def V######(device_type, device_name)  ➜  def V######(stig, ctx)
  • Drop the 3 boiler‑plate lines:
        check = Stig()
        check.set_vulid()
        check.status = "OP"
  • Replace exec_command(...) with ctx.exec(...)
    – keeps original command string
    – adds `.clean` / `.rendered` hints
The script writes *filename*.modified, shows a short diffstat,
and leaves the original untouched.
"""

import re, sys, difflib, pathlib, itertools

SRC   = pathlib.Path("cisco_stig_scanner_v4.1.3.AC.1.py")
DEST  = SRC.with_suffix(".py.modified")

FUNC_DEF_RE   = re.compile(r"^def (V\d{6,})(\s*)\((?:device_type\s*,\s*device_name)?\)\s*:")
BOILER_RE1    = re.compile(r"^\s*check\s*=\s*Stig\(\s*\)\s*$")
BOILER_RE2    = re.compile(r"^\s*check\.set_vulid\([^\)]*\)\s*$")
BOILER_RE3    = re.compile(r"^\s*check\.status\s*=\s*['\"]OP['\"]\s*$")
EXEC_CALL_RE  = re.compile(r"exec_command\(\s*([\"'].*?[\"'])\s*,\s*device_name\s*\)")

def transform(lines):
    out = []
    for line in lines:
        m = FUNC_DEF_RE.match(line)
        if m:
            funcname, space = m.groups()
            out.append(f"def {funcname}(stig, ctx):\n")
            continue
        if BOILER_RE1.match(line) or BOILER_RE2.match(line) or BOILER_RE3.match(line):
            continue  # drop boiler‑plate
        line = EXEC_CALL_RE.sub(r"ctx.exec(\1).clean", line)
        out.append(line)
    return out

orig_lines = SRC.read_text().splitlines(keepends=True)
new_lines  = transform(orig_lines)
DEST.write_text("".join(new_lines))

# --- show diffstat ---
added = sum(1 for l in new_lines   if l.startswith('+'))
gone  = sum(1 for l in orig_lines  if l not in new_lines)
print(f"✓ Wrote {DEST.name}  (+{added}/-{gone} LOC)\n")
for diffline in itertools.islice(
        difflib.unified_diff(orig_lines, new_lines,
                             fromfile=str(SRC), tofile=str(DEST), n=3), 0, 200):
    sys.stdout.write(diffline)
if gone == 0:
    print("No changes detected; did you already run the script?")
