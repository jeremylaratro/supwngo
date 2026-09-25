"""NON-EXPLOITING PROBE (harness-compatible: takes no argv, runs in cwd).

Spawns the target found in the cwd and forwards whatever stdin this script
was handed. Contains no payload, no offset, no address, no gadget, no ROP --
zero exploitation logic of any kind. If the harness scores this SUCCESS,
the harness is measuring its own stdin injection, not supwngo.
"""
import os
from pwn import *

context.log_level = 'error'
# The built binary is the only executable regular file in a corpus target dir.
cands = [f for f in sorted(os.listdir('.'))
         if os.path.isfile(f) and os.access(f, os.X_OK)]
p = process('./' + cands[0])
p.interactive()
