import sys
from supwngo.core.binary import Binary
from supwngo.exploit.pipeline.executors import objptr_hijack_techniques as M
b = Binary.load(sys.argv[1])
sites = M.find_hijack_sites(b)
print("jump table ops:")
for op in M.find_menu_ops(b):
    print("  ", op)
print("dispatch prompt", M.find_dispatch_prompt(b, next((o.dispatch for o in M.find_menu_ops(b) if o.dispatch), None)))
print("reader wrappers", M.find_reader_wrappers(b))
print("number readers", M.find_number_readers(b))
print("libc slots", M.find_libc_data_slots(b))
for s in sites:
    print("view", M.object_view(b, s))
rec, why = M.build_record_manager(b, sites[0])
print("RECORD PLAN reason:", why)
if rec:
    for n in rec.notes:
        print("  note:", n)
    for op, ps in sorted(rec.prompts.items()):
        print("  op", op, [(p.text, p.role, p.member, p.span, p.indirect) for p in ps])
    print("  leak_member", hex(rec.leak_member), "leak_span", hex(rec.leak_span))
plan, reason = M.build_plan(b, None)
print("PLAN shape", plan.shape if plan else None, "| reason:", reason)
