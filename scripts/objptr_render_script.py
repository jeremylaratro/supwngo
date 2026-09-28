"""Render the objptr_hijack executor's generated script for a target.

Optional MUTATION arguments let a caller change ONE recovered constant to a
real-but-wrong value, which is how the script's own validators are proven able
to go RED rather than assumed able.
"""
import sys
from supwngo.core.binary import Binary
from supwngo.core.context import ExploitContext
from supwngo.exploit.pipeline.executors import objptr_hijack_techniques as M

path, out = sys.argv[1], sys.argv[2]
muts = dict(a.split("=", 1) for a in sys.argv[3:])

b = Binary.load(path)
plan, reason = M.build_plan(b, None)
if plan is None:
    print("NO PLAN:", reason); sys.exit(2)
r = plan.record
for k, v in muts.items():
    v = int(v, 0)
    if k == "installed_fn":
        r.installed_fn = v
    elif k == "ptr_member":
        r.view.ptr_member = v
    elif k == "arg_member":
        r.view.arg_member = v
    elif k == "record_size":
        r.record_size = v
    elif k == "leak_span":
        r.leak_span = v
    elif k == "libc_slot":
        r.libc_slots = [M.LibcDataSlot(v, r.libc_slots[0].symbol, "MUTATED")]
    else:
        print("unknown mutation", k); sys.exit(2)
    print("MUTATED %s -> %#x" % (k, v))

ctx = ExploitContext(binary=b)
script = M.ObjPtrHijackExecutor()._script(ctx, plan)
open(out, "w").write(script)
print("wrote", out, len(script), "bytes, shape", plan.shape)
