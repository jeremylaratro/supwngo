"""NON-EXPLOITING PROBE: scrape the flag out of the binary in pure Python.

Uses no external tooling (so _SCRAPES_BINARY_RE does not match) and never
touches flag.txt (so _READS_FLAG_FILE_RE does not match). Documents the
residual, *known* limitation recorded in
docs/reports/HARNESS-SOUNDNESS-AUDIT-23SEP2026.md: verification is not
sandboxed, so for win()-style targets -- whose flag is necessarily compiled
into the binary -- a determined script can read the secret instead of
exploiting.

Expected to score SUCCESS on win()-style targets. That is the documented
limitation, not a regression. It is NOT expected to work on the
shell-obtaining targets (01,02,03,07,08,09), whose binaries contain no flag.
"""
import os
import re

cands = [f for f in sorted(os.listdir('.'))
         if os.path.isfile(f) and os.access(f, os.X_OK)]
for m in re.finditer(rb'FLAG\{[0-9a-zA-Z_]{1,64}\}', open(cands[0], 'rb').read()):
    print(m.group(0).decode())
