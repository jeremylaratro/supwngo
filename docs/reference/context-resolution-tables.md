# Context resolution: normative tables

**Generated** by `python -m supwngo.schema.resolve --emit-tables`.
Do not hand-edit: `tests/test_context_resolve_properties.py` asserts this
file is byte-identical to freshly generated output, and every cell below is
produced by calling the runtime comparator rather than read from a table.

Legend: `≻` row dominates column, `≺` column dominates row,
`=` equal, `∥` incomparable (neither dominates -- resolution refuses).

### Provenance precedence

| row ≻ col? | measured | derived | assumed | asserted | unknown |
|---|---|---|---|---|---|
| **measured** | = | ≻ | ≻ | ∥ | ≻ |
| **derived** | ≺ | = | ≻ | ∥ | ≻ |
| **assumed** | ≺ | ≺ | = | ≺ | ≻ |
| **asserted** | ∥ | ∥ | ≻ | = | ≻ |
| **unknown** | ≺ | ≺ | ≺ | ≺ | = |

### Scope specificity

| row ≻ col? | build | libc_file | host | boot | process | attempt |
|---|---|---|---|---|---|---|
| **build** | = | ∥ | ≺ | ≺ | ≺ | ≺ |
| **libc_file** | ∥ | = | ∥ | ∥ | ≺ | ≺ |
| **host** | ≻ | ∥ | = | ≺ | ≺ | ≺ |
| **boot** | ≻ | ∥ | ≻ | = | ≺ | ≺ |
| **process** | ≻ | ≻ | ≻ | ≻ | = | ≺ |
| **attempt** | ≻ | ≻ | ≻ | ≻ | ≻ | = |

### Candidate state transitions

| state | append | supersede | retract |
|---|---|---|---|
| **absent** | active | REFUSED | REFUSED |
| **active** | REFUSED | superseded | retracted |
| **superseded** | REFUSED | REFUSED | REFUSED |
| **retracted** | REFUSED | REFUSED | REFUSED |

### Merge decisions

| store already holds | decision |
|---|---|
| nothing | `appended` |
| an active candidate with the same dedup key | `deduped` |
| an active candidate, same value, different provenance | `appended` |
| an active candidate, same value, different method | `appended` |
| an active candidate with a different value | `appended` |
| only a **retracted** candidate with the same dedup key | `appended` |
| anything, and the incoming state is not `active` | `SchemaError (only the state machine changes states)` |
| anything, and the incoming candidate fails validation | `SchemaError (precondition, not a case)` |

### Per-key allowed scopes

`allowed scopes` is **enforced** by validation (invariant I4).
`depends_on` and `verification class` are **declarations for the
Phase-2 document layer**: this module has no loaded binary and no
tooling, so it performs no verification and does not pretend to.
They are listed here so the declaration is reviewable, not because
resolution consults them.

| fact key | allowed scopes | depends_on | verification class (declared) |
|---|---|---|---|
| `heap.base` | process | `runtime` | `runtime` |
| `libc.base` | process | `runtime` | `runtime` |
| `libc.binsh_offset` | libc_file | `libc_file` | `libc_offset` |
| `libc.system_offset` | libc_file | `libc_file` | `libc_offset` |
| `protections.canary` | build | `binary_bytes` | `unverifiable` |
| `protections.nx` | build | `binary_bytes` | `unverifiable` |
| `protections.pie` | build | `binary_bytes` | `unverifiable` |
| `stack.canary_offset` | build | `binary_bytes` | `static_offset` |
| `stack.return_offset` | build | `binary_bytes` | `static_offset` |
| `attempt.*` | attempt | `runtime` | `runtime` |
| `env.*` | boot, host | `runtime` | `runtime` |
| `gadget.*` | build | `binary_bytes` | `instruction_at` |
| `leak.*` | process | `runtime` | `runtime` |
| `libc.one_gadget.*` | libc_file | `libc_file` | `libc_offset` |
| `plt.*` | build | `binary_symbols` | `instruction_at` |
| `sym.*` | build | `binary_symbols` | `symbol_addr` |
