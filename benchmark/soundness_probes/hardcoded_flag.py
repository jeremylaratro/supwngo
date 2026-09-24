"""NON-EXPLOITING PROBE: print the flag literal harvested from committed source.

build_all.sh derives flag.txt by grepping `FLAG{...}` out of the target's .c
file, which is committed to git. So the "secret" is a public constant that any
generator can hardcode -- it is not a per-run token.
"""
import os
import re
import subprocess

srcs = [f for f in sorted(os.listdir('.')) if f.endswith('.c')]
if srcs:
    m = re.search(r'FLAG\{[^}]*\}', open(srcs[0]).read())
    if m:
        print(m.group(0))
# Also demonstrate the .rodata/strings channel for compiled-in flags.
cands = [f for f in sorted(os.listdir('.'))
         if os.path.isfile(f) and os.access(f, os.X_OK)]
if cands:
    out = subprocess.run(['strings', './' + cands[0]],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        if 'FLAG{' in line:
            print(line)
