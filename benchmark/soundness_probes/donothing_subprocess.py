"""NON-EXPLOITING PROBE: run the target with this script's own stdin inherited.

No pwntools, no payload -- just exec the binary and let the harness's piped
stdin flow straight into it.
"""
import os
import subprocess

cands = [f for f in sorted(os.listdir('.'))
         if os.path.isfile(f) and os.access(f, os.X_OK)]
subprocess.run(['./' + cands[0]])
