#!/usr/bin/env python3
"""
pass5_autofix.py – last mechanical sweep inside V-checks
"""
import re, pathlib, sys, itertools, difflib

SRC  = pathlib.Path("cisco_stig_scanner_v4.1.3.AC.2.pass4.fixed.clean.py")
DEST = SRC.with_suffix(".pass5.py")
TODO = pathlib.Path("pass5_todo.log")

FUNC_START = re.compile(r'^def V\d{6}\(')          # start of a V-check
EXEC_CMD   = re.compile(r'exec_command\(\s*([\'"].+?[\'"])\s*,\s*device_name\s*\)')
PROMPT_SLICE = re.compile(r'res\.clean\[\s*len\(device_name\)\s*\+\s*len\(command\)\s*:\s*\]')
RESULT_RHS = re.compile(r'\bresult\b')
RESULT_LHS = re.compile(r'^\s*result\s*=')

out, todo = [], []
in_vcheck = False

for lineno, line in enumerate(SRC.read_text().splitlines(keepends=True), 1):
    if FUNC_START.match(line):
        in_vcheck = True
    elif line.startswith("def ") and not FUNC_START.match(line):
        in_vcheck = False

    if in_vcheck:
        # 1. exec_command → scan_ctx.exec(...).clean
        m = EXEC_CMD.search(line)
        if m:
            cmd = m.group(1)
            line = EXEC_CMD.sub(f'scan_ctx.exec({cmd}).clean', line)

        # 2. remove prompt slice
        line = PROMPT_SLICE.sub('res.clean', line)

        # 3. result → res.clean (RHS only)
        if not RESULT_LHS.match(line):
            line = RESULT_RHS.sub('res.clean', line)

        # 4. todo marker
        if 'device_name' in line:
            todo.append(f"{SRC.name}:{lineno}: {line.rstrip()}")

    out.append(line)

DEST.write_text(''.join(out))
TODO.write_text('\n'.join(todo))

print(f"✓ wrote {DEST.name}")
print(f"⚠ {len(todo)} lines still reference 'device_name' – review manually in pass5_todo.log")
diff = difflib.unified_diff(
    SRC.read_text().splitlines(keepends=True), out,
    fromfile=str(SRC), tofile=str(DEST), n=1)
for d in itertools.islice(diff, 0, 60):
    sys.stdout.write(d)
