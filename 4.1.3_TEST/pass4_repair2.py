#!/usr/bin/env python3
"""
pass4_repair2.py – final mechanical fixes after auto-pass 4
  • restore any variable / parameter that was turned into "res.clean"
  • put support helpers (exec_command / handle_errors / pass_handle_errors)
    back into a compiling state.
  • clean accidental doc-string text.
Anything still containing `device_name` after this pass
remains in pass4_todo.log for human judgement.
"""

import re, pathlib, difflib, itertools, sys

SRC  = pathlib.Path("cisco_stig_scanner_v4.1.3.AC.2.pass4.fixed.py")
DEST = SRC.with_suffix(".clean.py")
TODO = pathlib.Path("pass4_todo.log")

text = SRC.read_text()

# --- 1. Parameters or LHS identifiers named "res.clean" -------------
text = re.sub(r'\bres\.clean\b(?=\s*[=,)]|\s*:)', 'result', text)

# --- 2. Function signatures -----------------------------------------
text = re.sub(r'def\s+(\w+)\s*\(\s*res\.clean\s*,', r'def \1(result, ', text)

# --- 3. Support-function bodies -------------------------------------
# exec_command   – revert inner refs back to result
text = re.sub(
    r'res\.clean = send_command',
    'result = send_command',
    text)

text = re.sub(
    r'res\.clean = handle_errors\(res\.clean,',
    'result = handle_errors(result,',
    text)

text = text.replace(
    'cleaned_output = command_cache.clean_output(res.clean)',
    'cleaned_output = command_cache.clean_output(result)')

# handle_errors pipes
text = re.sub(r'return crt_handle_errors\(res\.clean,', 'return crt_handle_errors(result,', text)
text = re.sub(r'return pass_handle_errors\(res\.clean,', 'return pass_handle_errors(result,', text)
text = text.replace('len(res.clean)', 'len(result)')
text = text.replace('return res.clean', 'return result')

# pass_handle_errors param doc-string
text = text.replace('- res.clean (str):', '- result (str):')

# --- 4. Doc-string / comment touch-ups ------------------------------
text = text.replace('vulnerability res.clean', 'vulnerability result')

# --- 5. Write out and show a diff preview ---------------------------
DEST.write_text(text)

print(f"✓ wrote {DEST.name}")

diff = difflib.unified_diff(
    SRC.read_text().splitlines(keepends=True),
    text.splitlines(keepends=True),
    fromfile=str(SRC), tofile=str(DEST), n=1)
for line in itertools.islice(diff, 0, 120):
    sys.stdout.write(line)

print("\nNOW run  ➜  python -m py_compile", DEST.name)
print("Then work through pass4_todo.log for the lines that still reference"
      " device_name  or leftover 'result' inside V-checks.")
