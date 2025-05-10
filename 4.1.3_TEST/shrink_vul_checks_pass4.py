#!/usr/bin/env python3
"""
Auto-pass 4 – bulk-clean remaining V-checks
------------------------------------------

Transforms
 1. exec_command(cmd, device_name)  ➜  res = scan_ctx.exec(cmd).clean
    – inserts the new 'res' line, removes the old exec_command line
 2. result[len(device_name) + len(command):]  ➜  res.clean   (only for SAME 'command')
 3. stig.finding = result              ➜  stig.finding = res.rendered
 4. bare 'result' (logic checks)      ➜  res.clean
 5. check.                            ➜  stig.
 6. return check                      (deleted)
 7. whole-word ctx                    ➜  scan_ctx

Any line that still contains 'device_name' OR 'result' after edits is
logged to pass4_todo.log for manual review.

Outputs
  • <SRC>.pass4.py
  • pass4_todo.log           (lines needing human review)
"""

import re
import pathlib
import difflib
import itertools
import sys

SRC  = pathlib.Path("cisco_stig_scanner_v4.1.3.AC.2.py")
DEST = SRC.with_suffix(".pass4.py")
TODO = pathlib.Path("pass4_todo.log")

# Regex patterns
EXEC_RE   = re.compile(r'^\s*(\w+)\s*=\s*exec_command\(\s*(\w+)\s*,\s*device_name\s*\)')
SLICE_TMPL= r'result\[\s*len\(device_name\)\s*\+\s*len\({cmd}\)\s*:\s*\]'
RESULT_RE = re.compile(r'\bresult\b')
CHECK_RE  = re.compile(r'\bcheck\.')
CTX_RE    = re.compile(r'\bctx\b')
RET_CHECK = re.compile(r'^\s*return\s+check\b')

todo_lines = []

def transform(lines):
    out      = []
    cmd_var  = None   # remembers the name of the 'command' variable in current function

    for lineno, line in enumerate(lines, 1):
        # Detect new function start to reset cmd_var
        if line.startswith("def V") and '(stig' in line:
            cmd_var = None

        # 1) exec_command → res = scan_ctx.exec(...)
        m = EXEC_RE.match(line)
        if m:
            cmd_var, cmd_name = m.groups()   # usually ('result','command') -> cmd_var='result'?? Actually variable capturing: first group is lhs variable name e.g., result; second group is cmd variable 'command'
            # insert new line using the same cmd variable
            out.append(f"    res = scan_ctx.exec({cmd_name})\n")
            continue                         # skip the original exec_command line

        # 2) slice removal if pattern matches current cmd_var
        if cmd_var:
            slice_re = re.compile(SLICE_TMPL.format(cmd=cmd_var))
            line = slice_re.sub('res.clean', line)

        # 3) convert stig.finding assignment
        if 'stig.finding' in line and 'result' in line:
            line = line.replace('result', 'res.rendered')
        else:
            # replace bare 'result' words that aren't part of res.rendered
            line = RESULT_RE.sub(lambda m: 'res.clean' if m.group(0) == 'result' else m.group(0), line)

        # 4) check. → stig.
        line = CHECK_RE.sub('stig.', line)

        # 5) drop 'return check'
        if RET_CHECK.match(line):
            continue

        # 6) ctx → scan_ctx (guard)
        line = CTX_RE.sub('scan_ctx', line)

        # collect TODOs
        if 'device_name' in line or ('result' in line and 'res.' not in line):
            todo_lines.append(f"{SRC.name}:{lineno}: {line.rstrip()}")

        out.append(line)
    return out

NEW_LINES = transform(SRC.read_text().splitlines(keepends=True))
DEST.write_text(''.join(NEW_LINES))
TODO.write_text('\n'.join(todo_lines))

print(f"✓ Wrote {DEST.name}")
print(f"⚠ Logged {len(todo_lines)} potential manual-review lines to {TODO}")
if todo_lines:
    print("   Open pass4_todo.log and clear the remaining cases by hand.\n")

    # preview first diff hunk
    diff_iter = difflib.unified_diff(
        SRC.read_text().splitlines(keepends=True),
        NEW_LINES,
        fromfile=str(SRC),
        tofile=str(DEST),
        n=2
    )
    for d in itertools.islice(diff_iter, 0, 120):
        sys.stdout.write(d)
