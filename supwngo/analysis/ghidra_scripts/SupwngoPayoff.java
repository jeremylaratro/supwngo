// SupwngoPayoff.java - headless Ghidra payoff-evidence extractor for supwngo.
//
// Driven by supwngo.analysis.payoff.rank_payoffs via analyzeHeadless. Like
// SupwngoDecompile.java this MUST live in its own near-empty directory (Ghidra
// enumerates every file in each -scriptPath dir to classify scripts) and is a
// .java script deliberately (Ghidra 12.x without PyGhidra cannot run .py).
//
// Directive W, phase W-1: identify a binary's payoff ("win") function from
// static evidence, NOT from hardcoded names. For every real (non-thunk,
// non-external) function this emits the evidence the Python ranker scores:
//   - the sink calls it makes (exec/file-open family) and, for each, the
//     tri-state provenance of that sink's path/command argument;
//   - whether it performs a light disclosure (a read-family call AND an output
//     to stdout), needed to turn a fixed-path open into a FILE_FIXED atom;
//   - whether any call edge in the program targets it (UNREFERENCED, a rank
//     tie-breaker only -- never a gate, since main/fillers/decoys are uncalled
//     too; see plan R3).
//
// Directive W, phase W-2 (design doc docs/plans/2026-11-13-w2-required-args-
// design.md, Rev 11): for every function with at least one const-string-target
// sink, additionally determine the formal-parameter constants the caller must
// supply to *guarantee* reaching that sink -- a required-args pass over the
// decompiled P-code (see §2). This never changes the W-1 evidence fields; it
// adds three per-record fields (below) populated by extractRequiredArgs(),
// which runs inside analyze() while hf/op are still live and is wrapped in its
// own try/catch so a per-function analysis failure never degrades the W-1
// pass for that function (it only taints that function's args_status).
//
// Output envelope (a single UTF-8 JSON OBJECT written to arg0 so the caller can
// tell "ran, analyzed everything, found nothing" from "never ran" and from
// "ran but a function failed"):
//   {
//     "script_version": "w2.0",
//     "backend_base":   <image base, unsigned>,
//     "enumerated":     <real functions seen>,
//     "analyzed":       <real functions whose body was extracted>,
//     "failed":         <real functions whose decompile failed>,
//     "records": [ {
//        "address": <function entry, unsigned, in Ghidra's convention>,
//        "name": "<raw symbol name>",
//        "sinks": [ { "api": "<canonical import>",
//                     "target": { "kind": "const_string|param|unknown",
//                                 "address": <unsigned|null>, "value": <str|null> } } ],
//        "has_read": <bool>, "has_stdout_output": <bool>, "unreferenced": <bool>,
//        "args_status": "known|unknown",
//        "args_reason": <str|null>,   // null iff args_status=="known"
//        "required_args": [ { "position": <int>, "value": <int>,
//             "slot": <int>, "width_bits": <int>, "src_width_bits": <int>,
//             "terminal": "HighParam", "reg": <str|null>,
//             "op": "INT_EQUAL|INT_NOTEQUAL", "op_addr": <unsigned>,
//             "sink_addrs": [<unsigned>, ...], "transform": [<str>, ...] }, ... ]
//     }, ... ]
//   }
// The caller maps each record's "address" to the corpus RVA with
// rva = address - backend_base (payoff.to_corpus_rva) and enforces the COMPLETE
// invariant (valid marker, failed == 0, analyzed == enumerated).
//
// Script args (positional):
//   arg0  output JSON path
//   arg1  entry point as an offset from the image base (hex RVA), or "none"
//   arg2  file format: "elf", "pe" or "unknown"
//@category Supwngo

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class SupwngoPayoff extends GhidraScript {

    private static final String SCRIPT_VERSION = "w2.0";

    /** Tracer bounds: def-use depth and a per-byte string-read cap. */
    private static final int TRACE_DEPTH = 40;
    private static final int STRING_MAX = 256;

    /** Sink and disclosure API families, matched on the canonical import name. */
    private static final Set<String> EXEC_FAMILY = setOf(
            "system", "execve", "execl", "execlp", "execle",
            "execv", "execvp", "execvpe", "popen");
    private static final Set<String> FILE_OPEN_FAMILY = setOf("open", "openat", "fopen");
    private static final Set<String> READ_FAMILY = setOf(
            "read", "fread", "pread", "fgets", "fscanf", "fgetc", "getc", "getline");
    private static final Set<String> STDOUT_FAMILY = setOf(
            "write", "fwrite", "puts", "fputs", "printf", "fprintf", "putchar", "putc");

    /** Tri-state provenance kinds, mirrored in payoff.TargetTrace. */
    private static final String CONST_STRING = "const_string";
    private static final String PARAM = "param";
    private static final String UNKNOWN = "unknown";

    // ---- W-2 required-args constants (design §2) ----

    /** Role of a resolved compare's two operands (§2.1 classifier). */
    private static final int ROLE_NON_GATE = 0;
    private static final int ROLE_AMBIGUOUS_PARAM = 1;
    private static final int ROLE_PINNABLE = 2;
    private static final int ROLE_NONCONST_PARAM = 3;

    private static final Set<Integer> BOOL_COMBINATORS = intSetOf(
            PcodeOp.BOOL_AND, PcodeOp.BOOL_OR, PcodeOp.BOOL_XOR,
            PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR);
    private static final Set<Integer> COMPARISON_OPS = intSetOf(
            PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_SLESS,
            PcodeOp.INT_SLESSEQUAL, PcodeOp.INT_LESS, PcodeOp.INT_LESSEQUAL);
    private static final Set<Integer> EQUALITY_OPS = intSetOf(
            PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL);

    /** §2.2 bound on Step 2's cartesian enumeration: 4096 = 2^12. */
    private static final int ENUM_CAP = 4096;

    /** §2.2 reason precedence, highest first. */
    private static final List<String> REASON_PRECEDENCE = Arrays.asList(
            "irreducible_cflow", "analysis_exception", "conflict", "abi_class",
            "bool_compose", "bool_fanout", "ambiguous_gate", "nonconst_gate",
            "avoidance_gate", "relational_gate", "unresolved_gate");

    /** §3: the SysV integer argument base registers an emitted arg may name. */
    private static final Set<String> SYSV_INT_BASE_REGS = setOf(
            "RDI", "RSI", "RDX", "RCX", "R8", "R9");

    private static final String KNOWN = "known";
    private static final String UNKNOWN_STATUS = "unknown";

    private DecompInterface decomp;

    private static Set<String> setOf(String... names) {
        return new HashSet<>(Arrays.asList(names));
    }

    private static Set<Integer> intSetOf(int... vals) {
        Set<Integer> s = new HashSet<>();
        for (int v : vals) {
            s.add(v);
        }
        return s;
    }

    /** Minimal RFC-8259 string escaping (no JSON library on the path). */
    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                case '\b': b.append("\\b"); break;
                case '\f': b.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        return b.toString();
    }

    /** Parse "0x.." hex or decimal; null when absent or unparseable. */
    private static Long parseOffset(String text) {
        if (text == null) {
            return null;
        }
        String a = text.trim();
        try {
            return a.toLowerCase().startsWith("0x")
                    ? Long.parseUnsignedLong(a.substring(2), 16)
                    : Long.parseUnsignedLong(a);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Canonical import identity (mirrors payoff.canonical_import, MAJOR 6): drop
     * a "@plt"/"@GLIBC_*" version suffix, a PE "__imp_" prefix and a single
     * leading underscore. Case is significant. Matching families on this form
     * means PLT/IAT/thunk spellings all resolve.
     */
    private static String canonicalImport(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        String name = raw;
        int at = name.indexOf('@');
        if (at >= 0) {
            name = name.substring(0, at);
        }
        name = name.trim();
        if (name.startsWith("__imp_")) {
            name = name.substring("__imp_".length());
        }
        if (name.startsWith("_") && name.length() > 1) {
            name = name.substring(1);
        }
        return name;
    }

    /**
     * The pcode-input index of a sink's path/command argument (plan R1). Pcode
     * CALL input 0 is the call target, so argument N is input N+1: arg0 for
     * every family member except openat (arg1 -> input 2).
     */
    private static int pathInputIndex(String canonicalApi) {
        return "openat".equals(canonicalApi) ? 2 : 1;
    }

    /** One traced target: kind plus, for a constant string, its address/value. */
    private static final class Trace {
        final String kind;
        final Long address;
        final String value;

        Trace(String kind, Long address, String value) {
            this.kind = kind;
            this.address = address;
            this.value = value;
        }

        static final Trace UNK = new Trace(UNKNOWN, null, null);
        static final Trace PAR = new Trace(PARAM, null, null);
    }

    /**
     * Read a NUL-terminated printable C string at addr, or null when the bytes
     * are not a plausible string. This validates a constant pointer as pointing
     * into defined string data (MAJOR 4) rather than trusting any integer
     * constant; a non-string constant falls through to UNKNOWN (fail closed).
     */
    private String readCString(Address addr) {
        if (addr == null) {
            return null;
        }
        try {
            StringBuilder b = new StringBuilder();
            for (int i = 0; i < STRING_MAX; i++) {
                byte raw = currentProgram.getMemory().getByte(addr.add(i));
                int u = raw & 0xff;
                if (u == 0) {
                    return b.length() > 0 ? b.toString() : null;
                }
                boolean printable = (u >= 0x20 && u <= 0x7e)
                        || u == 0x09 || u == 0x0a || u == 0x0d;
                if (!printable) {
                    return null;
                }
                b.append((char) u);
            }
            return null;
        } catch (MemoryAccessException e) {
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /** A constant varnode read as a string-data pointer, else null. */
    private Trace constStringAt(long offset) {
        try {
            Address a = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(offset);
            String s = readCString(a);
            if (s != null) {
                return new Trace(CONST_STRING, a.getOffset(), s);
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    /** True when the varnode's high variable is a formal parameter (plan R2). */
    private static boolean isParameterVarnode(Varnode v) {
        HighVariable hv = v.getHigh();
        if (hv == null) {
            return false;
        }
        HighSymbol sym = hv.getSymbol();
        return sym != null && sym.isParameter();
    }

    /**
     * Bounded, cycle-safe def-use trace of a call-argument varnode to one of
     * CONST_STRING / PARAM / UNKNOWN (plan 2.2). A formal parameter stays PARAM
     * even when every current caller passes a literal (intra-procedural, R2).
     * Any unhandled op defaults to UNKNOWN -- UNKNOWN never becomes a candidate
     * (fail closed), so the decoy's parameter is never mistyped as a constant.
     */
    private Trace traceTarget(Varnode v, int depth, Set<Varnode> seen) {
        if (v == null || depth <= 0 || !seen.add(v)) {
            return Trace.UNK;
        }
        if (v.isConstant()) {
            Trace t = constStringAt(v.getOffset());
            return t != null ? t : Trace.UNK;
        }
        if (isParameterVarnode(v)) {
            return Trace.PAR;
        }
        PcodeOp d = v.getDef();
        if (d == null) {
            return Trace.UNK;
        }
        int opc = d.getOpcode();
        switch (opc) {
            case PcodeOp.PTRSUB:
                if (d.getInput(0).isConstant() && d.getInput(0).getOffset() == 0
                        && d.getInput(1).isConstant()) {
                    Trace t = constStringAt(d.getInput(1).getOffset());
                    return t != null ? t : Trace.UNK;
                }
                return Trace.UNK;
            case PcodeOp.COPY:
            case PcodeOp.CAST:
            case PcodeOp.INT_ZEXT:
            case PcodeOp.INT_SEXT:
            case PcodeOp.SUBPIECE:
            case PcodeOp.INDIRECT:
                return traceTarget(d.getInput(0), depth - 1, seen);
            case PcodeOp.MULTIEQUAL:
                return traceMulti(d, depth, seen);
            default:
                return Trace.UNK;
        }
    }

    /**
     * MULTIEQUAL (phi) join, fail closed: a constant only when every input is
     * the same constant string; any parameter input makes it PARAM (a
     * disqualifier, never a candidate); anything mixed is UNKNOWN.
     */
    private Trace traceMulti(PcodeOp phi, int depth, Set<Varnode> seen) {
        Long constAddr = null;
        String constVal = null;
        boolean anyParam = false;
        boolean allConst = phi.getNumInputs() > 0;
        for (int i = 0; i < phi.getNumInputs(); i++) {
            Trace t = traceTarget(phi.getInput(i), depth - 1, seen);
            if (PARAM.equals(t.kind)) {
                anyParam = true;
                allConst = false;
            } else if (CONST_STRING.equals(t.kind)) {
                if (constAddr == null) {
                    constAddr = t.address;
                    constVal = t.value;
                } else if (!constAddr.equals(t.address)) {
                    allConst = false;
                }
            } else {
                allConst = false;
            }
        }
        if (allConst && constAddr != null) {
            return new Trace(CONST_STRING, constAddr, constVal);
        }
        return anyParam ? Trace.PAR : Trace.UNK;
    }

    /**
     * Names a CALL/CALLIND resolves to: the callee and its thunk target, plus
     * the symbols and external labels the call site (and the GOT/IAT slot)
     * refer to. An indirect call through a dynamic import has no callee function
     * in the program, only these references. (Mirrors SupwngoDecompile.)
     */
    private Set<String> calleeNames(PcodeOp op) {
        Set<String> names = new HashSet<>();
        Address site = op.getSeqnum().getTarget();
        if (op.getOpcode() == PcodeOp.CALL) {
            Function c = currentProgram.getFunctionManager()
                    .getFunctionAt(op.getInput(0).getAddress());
            if (c != null) {
                names.add(c.getName());
                Function t = c.getThunkedFunction(true);
                if (t != null) {
                    names.add(t.getName());
                }
            }
        }
        for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(site)) {
            if (!r.getReferenceType().isCall()) {
                continue;
            }
            Symbol sy = currentProgram.getSymbolTable().getPrimarySymbol(r.getToAddress());
            if (sy != null) {
                names.add(sy.getName());
            }
            if (r instanceof ExternalReference) {
                names.add(((ExternalReference) r).getLabel());
            }
        }
        return names;
    }

    private static boolean isCallOp(PcodeOp op) {
        return op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND;
    }

    private HighFunction highOf(Function f) {
        DecompileResults res = decomp.decompileFunction(f, 60, new ConsoleTaskMonitor());
        return res == null ? null : res.getHighFunction();
    }

    private boolean isRealFunction(Function f) {
        return f != null && !f.isThunk() && !f.isExternal();
    }

    /** Any call-type reference anywhere in the program targets f's entry. */
    private boolean hasIncomingCall(Function f) {
        Iterator<Reference> it = currentProgram.getReferenceManager()
                .getReferencesTo(f.getEntryPoint()).iterator();
        while (it.hasNext()) {
            if (it.next().getReferenceType().isCall()) {
                return true;
            }
        }
        return false;
    }

    // =====================================================================
    // W-2 required-args extraction (design §2). Everything below is additive:
    // it reads the HighFunction produced for W-1 and never changes a W-1 field.
    // =====================================================================

    /** §2.1 slot lattice: NONPARAM, PARAM ⊑ MEM ⊑ AMBIGUOUS (top). */
    private enum SlotKind { NONPARAM, PARAM, MEM, AMBIGUOUS }

    /** One operand's classification. slot/widthBits/transform valid iff PARAM. */
    private static final class SlotInfo {
        final SlotKind kind;
        final int slot;
        final int widthBits;
        final List<Integer> transform;

        private SlotInfo(SlotKind kind, int slot, int widthBits, List<Integer> transform) {
            this.kind = kind;
            this.slot = slot;
            this.widthBits = widthBits;
            this.transform = transform;
        }

        static final SlotInfo NONPARAM =
                new SlotInfo(SlotKind.NONPARAM, -1, 0, Collections.<Integer>emptyList());
        static final SlotInfo MEM =
                new SlotInfo(SlotKind.MEM, -1, 0, Collections.<Integer>emptyList());
        static final SlotInfo AMBIGUOUS =
                new SlotInfo(SlotKind.AMBIGUOUS, -1, 0, Collections.<Integer>emptyList());

        static SlotInfo param(int slot, int widthBits, List<Integer> transform) {
            return new SlotInfo(SlotKind.PARAM, slot, widthBits, transform);
        }
    }

    /**
     * §2.1 transfer function. `sibling` is the compare's other operand, needed
     * only to validate a ZEXT/SEXT's canonical round-trip; may be null when
     * tracing a non-top-level input (MULTIEQUAL arms, generic op inputs).
     */
    private SlotInfo traceParamSlot(Varnode v, Varnode sibling, int depth) {
        if (v == null || depth <= 0) {
            return SlotInfo.AMBIGUOUS;
        }
        if (v.isConstant()) {
            return SlotInfo.NONPARAM;
        }
        HighVariable hv = v.getHigh();
        if (v.isInput() && hv instanceof HighParam) {
            HighParam hp = (HighParam) hv;
            if (v.getSize() == hv.getSize()) {
                return SlotInfo.param(hp.getSlot(), 8 * v.getSize(), new ArrayList<Integer>());
            }
            return SlotInfo.AMBIGUOUS; // a partial view of the parameter's storage
        }
        PcodeOp d = v.getDef();
        if (d == null) {
            // A bare input varnode with no defining op and not the matched formal
            // above. Ghidra 12.1.3 empirically represents a global as exactly
            // this (no LOAD op) -- the design's MEM substitute for LOAD. But a
            // direct CALL/BRANCH's hardcoded target address is *also* a bare
            // no-def "ram"-space input with no HighVariable at all, and is not
            // a memory-resident *value* being read -- only a genuine recognized
            // data symbol (HighGlobal, carrying a HighVariable) is the LOAD
            // substitute; an address with no HighVariable is NONPARAM so it
            // never poisons an enclosing op's join (e.g. a CALL's own target
            // input must not taint the call's return value to AMBIGUOUS).
            return v.getAddress().isMemoryAddress() && v.getHigh() != null
                    ? SlotInfo.MEM : SlotInfo.NONPARAM;
        }
        int opc = d.getOpcode();
        switch (opc) {
            case PcodeOp.COPY: {
                SlotInfo s = traceParamSlot(d.getInput(0), sibling, depth - 1);
                return passThrough(s, opc);
            }
            case PcodeOp.CAST: {
                Varnode in0 = d.getInput(0);
                SlotInfo s = traceParamSlot(in0, sibling, depth - 1);
                if (in0.getSize() != v.getSize()) {
                    return joinDefault(s);
                }
                return passThrough(s, opc);
            }
            case PcodeOp.INT_ZEXT:
            case PcodeOp.INT_SEXT: {
                SlotInfo s = traceParamSlot(d.getInput(0), null, depth - 1);
                if (s.kind != SlotKind.PARAM) {
                    return joinDefault(s);
                }
                int extWidth = 8 * v.getSize();
                if (sibling != null && sibling.isConstant()) {
                    boolean ok = extendRoundTrips(
                            sibling.getOffset(), extWidth, s.widthBits, opc == PcodeOp.INT_SEXT);
                    if (!ok) {
                        return SlotInfo.AMBIGUOUS;
                    }
                }
                List<Integer> t = new ArrayList<>(s.transform);
                t.add(opc);
                return SlotInfo.param(s.slot, extWidth, t);
            }
            case PcodeOp.SUBPIECE:
                return SlotInfo.AMBIGUOUS;
            case PcodeOp.LOAD:
                return SlotInfo.MEM;
            case PcodeOp.INDIRECT:
            case PcodeOp.PTRSUB:
            case PcodeOp.PTRADD:
                return SlotInfo.AMBIGUOUS;
            case PcodeOp.MULTIEQUAL:
                return traceMultiSlot(d, depth);
            default:
                return joinDefaultOverInputs(d, depth);
        }
    }

    /** COPY / width-preserving CAST: PARAM/MEM pass through; else join to top. */
    private static SlotInfo passThrough(SlotInfo s, int opc) {
        if (s.kind == SlotKind.MEM) {
            return SlotInfo.MEM;
        }
        if (s.kind == SlotKind.PARAM) {
            List<Integer> t = new ArrayList<>(s.transform);
            t.add(opc);
            return SlotInfo.param(s.slot, s.widthBits, t);
        }
        return joinDefault(s);
    }

    /** The lattice join for an unlisted/non-value-preserving unary op. */
    private static SlotInfo joinDefault(SlotInfo s) {
        return s.kind == SlotKind.NONPARAM ? SlotInfo.NONPARAM : SlotInfo.AMBIGUOUS;
    }

    /** The lattice join for an unlisted n-ary op: any non-NONPARAM input -> top. */
    private SlotInfo joinDefaultOverInputs(PcodeOp d, int depth) {
        boolean anyNonNonparam = false;
        for (int i = 0; i < d.getNumInputs(); i++) {
            SlotInfo s = traceParamSlot(d.getInput(i), null, depth - 1);
            if (s.kind != SlotKind.NONPARAM) {
                anyNonNonparam = true;
            }
        }
        return anyNonNonparam ? SlotInfo.AMBIGUOUS : SlotInfo.NONPARAM;
    }

    /**
     * MULTIEQUAL (phi): PARAM(s,w) iff every non-self-referential arm is PARAM
     * with the same slot/width; NONPARAM iff every arm is NONPARAM; else
     * AMBIGUOUS (mixed PARAM+NONPARAM, two slots, or any MEM/AMBIGUOUS arm).
     */
    private SlotInfo traceMultiSlot(PcodeOp phi, int depth) {
        Varnode selfOutput = phi.getOutput();
        List<SlotInfo> arms = new ArrayList<>();
        for (int i = 0; i < phi.getNumInputs(); i++) {
            Varnode in = phi.getInput(i);
            if (selfOutput != null && in.equals(selfOutput)) {
                continue; // a true self-reference back-edge arm is ignored
            }
            arms.add(traceParamSlot(in, null, depth - 1));
        }
        if (arms.isEmpty()) {
            return SlotInfo.AMBIGUOUS;
        }
        boolean allNonparam = true;
        boolean allParamSameSlot = true;
        Integer commonSlot = null;
        Integer commonWidth = null;
        for (SlotInfo s : arms) {
            if (s.kind != SlotKind.NONPARAM) {
                allNonparam = false;
            }
            if (s.kind != SlotKind.PARAM) {
                allParamSameSlot = false;
            } else if (commonSlot == null) {
                commonSlot = s.slot;
                commonWidth = s.widthBits;
            } else if (commonSlot.intValue() != s.slot || commonWidth.intValue() != s.widthBits) {
                allParamSameSlot = false;
            }
        }
        if (allParamSameSlot) {
            return SlotInfo.param(commonSlot, commonWidth, new ArrayList<Integer>());
        }
        if (allNonparam) {
            return SlotInfo.NONPARAM;
        }
        return SlotInfo.AMBIGUOUS;
    }

    /**
     * §2.1 SEXT/ZEXT canonical round-trip: truncate constValue to srcWidthBits,
     * re-extend per `signExtend`, and require bit-equality at extWidthBits with
     * the original constant. Overflow-safe: a width >= 64 never reaches `1L <<
     * width` with a shift distance that needs masking protection because the
     * mask/sign-bit computation for that width is skipped (full 64-bit value).
     */
    private static boolean extendRoundTrips(
            long constValue, int extWidthBits, int srcWidthBits, boolean signExtend) {
        if (srcWidthBits <= 0 || extWidthBits <= 0) {
            return false;
        }
        long srcMask = (srcWidthBits >= 64) ? -1L : ((1L << srcWidthBits) - 1);
        long truncated = constValue & srcMask;
        long reExtended;
        if (signExtend && srcWidthBits < 64) {
            long signBit = 1L << (srcWidthBits - 1);
            reExtended = ((truncated & signBit) != 0) ? (truncated | ~srcMask) : truncated;
        } else {
            reExtended = truncated;
        }
        long extMask = (extWidthBits >= 64) ? -1L : ((1L << extWidthBits) - 1);
        return (reExtended & extMask) == (constValue & extMask);
    }

    /**
     * §2.1 compare-operand classifier, first match wins. c0/c1 are each
     * operand's isConstant().
     */
    private static int classifyCompare(SlotInfo s0, SlotInfo s1, boolean c0, boolean c1) {
        boolean p0 = s0.kind == SlotKind.PARAM;
        boolean p1 = s1.kind == SlotKind.PARAM;
        boolean mem0 = s0.kind == SlotKind.MEM;
        boolean mem1 = s1.kind == SlotKind.MEM;
        boolean amb0 = s0.kind == SlotKind.AMBIGUOUS;
        boolean amb1 = s1.kind == SlotKind.AMBIGUOUS;

        if (!p0 && !p1 && !mem0 && !mem1 && !amb0 && !amb1) {
            return ROLE_NON_GATE;
        }
        if (amb0 || amb1) {
            return ROLE_AMBIGUOUS_PARAM;
        }
        if (mem0 && !p1) {
            return ROLE_AMBIGUOUS_PARAM;
        }
        if (mem1 && !p0) {
            return ROLE_AMBIGUOUS_PARAM;
        }
        if (p0 && !p1 && !mem1 && c1) {
            return ROLE_PINNABLE;
        }
        if (p1 && !p0 && !mem0 && c0) {
            return ROLE_PINNABLE;
        }
        return ROLE_NONCONST_PARAM;
    }

    /** §2.2 walk-accumulated parity record, Ghidra-state-free. */
    static final class ResolvedComparison {
        final int cmpOpcode;
        final int negateParity;

        ResolvedComparison(int cmpOpcode, int negateParity) {
            this.cmpOpcode = cmpOpcode;
            this.negateParity = negateParity;
        }
    }

    /** Result of walking a CBRANCH's condition back to a resolved comparison. */
    private static final class ConditionWalk {
        final ResolvedComparison rc;       // null when unresolved
        final String unresolvedCause;      // null when resolved
        final PcodeOp terminalCmpOp;        // null when unresolved

        private ConditionWalk(ResolvedComparison rc, String cause, PcodeOp terminalCmpOp) {
            this.rc = rc;
            this.unresolvedCause = cause;
            this.terminalCmpOp = terminalCmpOp;
        }

        static ConditionWalk resolved(ResolvedComparison rc, PcodeOp op) {
            return new ConditionWalk(rc, null, op);
        }

        static ConditionWalk unresolved(String cause) {
            return new ConditionWalk(null, cause, null);
        }
    }

    /** §2.2 pure fold: one parity flip per BOOL_NEGATE peeled, Ghidra-state-free. */
    static int flipParity(int p) {
        return p ^ 1;
    }

    static int accumulateNegateParity(int[] peeledOpcodes) {
        int parity = 0;
        for (int opc : peeledOpcodes) {
            if (opc == PcodeOp.BOOL_NEGATE) {
                parity = flipParity(parity);
            }
        }
        return parity;
    }

    /** §2.2 the walk's record builder: stores the accumulated parity in rc. */
    static ResolvedComparison resolveConditionFromPeeled(int cmpOpcode, int[] peeledOpcodes) {
        return new ResolvedComparison(cmpOpcode, accumulateNegateParity(peeledOpcodes));
    }

    /** §2.2: true iff traversing edge e implies param == const. */
    static boolean edgeMeansEqual(boolean isTrueEdge, int negateParity, int cmpOpcode) {
        return isTrueEdge ^ (negateParity == 1) ^ (cmpOpcode == PcodeOp.INT_NOTEQUAL);
    }

    /** §2.2 Step 1's emit-vs-avoidance decision. */
    static boolean step1EmitsEquality(ResolvedComparison rc, boolean requiredEdgeIsTrue) {
        return edgeMeansEqual(requiredEdgeIsTrue, rc.negateParity, rc.cmpOpcode);
    }

    /** §2.2 Step 2's determined-edge selection. */
    static boolean step2SelectedEdgeIsTrue(ResolvedComparison rc, boolean assignmentEqualsConst) {
        boolean meansEqualOnTrueEdge = edgeMeansEqual(true, rc.negateParity, rc.cmpOpcode);
        return meansEqualOnTrueEdge == assignmentEqualsConst;
    }

    /**
     * True iff v is defined by a boolean/bitwise combinator (AND/OR/XOR) that
     * is itself composing two separate truth values -- i.e. at least one of
     * the combinator's OWN inputs is defined by a comparison op or
     * BOOL_NEGATE (the empirical gate_bool shape:
     * INT_NOTEQUAL(INT_AND(INT_EQUAL(a,X),flag),0), where the AND's input0 is
     * directly an INT_EQUAL's output). A bare arithmetic AND/OR/XOR over
     * ordinary values (e.g. Ghidra 12.1.3's own simplification of `a*2==X`
     * into `(sext(a) & 0x7fffffffffffffff) == X`, de-risk step 2) is NOT a
     * boolean composition: neither of ITS inputs is comparison-shaped, so
     * this returns false and the walk falls through to classify the compare's
     * operands via traceParamSlot/classifyCompare, where the arithmetic join
     * rule (any op not listed, with a PARAM input, joins to AMBIGUOUS)
     * correctly yields ambiguous_gate instead of a false bool_compose.
     */
    private static boolean isBoolComposition(Varnode v) {
        PcodeOp d = v.getDef();
        if (d == null || !BOOL_COMBINATORS.contains(d.getOpcode())) {
            return false;
        }
        for (int i = 0; i < d.getNumInputs(); i++) {
            PcodeOp inDef = d.getInput(i).getDef();
            if (inDef != null && (COMPARISON_OPS.contains(inDef.getOpcode())
                    || inDef.getOpcode() == PcodeOp.BOOL_NEGATE)) {
                return true;
            }
        }
        return false;
    }

    /**
     * §2.2 unary-only condition walk: peel COPY / width-preserving CAST /
     * INT_ZEXT / INT_SEXT / BOOL_NEGATE back to a single comparison op, or
     * report why it could not resolve (bool_compose / bool_fanout).
     */
    private ConditionWalk walkCondition(Varnode condition) {
        List<Integer> peeled = new ArrayList<>();
        Varnode cur = condition;
        for (int guard = 0; guard < TRACE_DEPTH; guard++) {
            if (cur == null) {
                return ConditionWalk.unresolved("bool_fanout");
            }
            PcodeOp d = cur.getDef();
            if (d == null) {
                return ConditionWalk.unresolved("bool_fanout");
            }
            int opc = d.getOpcode();
            boolean widthPreservingCast = opc == PcodeOp.CAST
                    && d.getInput(0).getSize() == cur.getSize();
            if (opc == PcodeOp.COPY || widthPreservingCast
                    || opc == PcodeOp.INT_ZEXT || opc == PcodeOp.INT_SEXT
                    || opc == PcodeOp.BOOL_NEGATE) {
                peeled.add(opc);
                cur = d.getInput(0);
                continue;
            }
            if (BOOL_COMBINATORS.contains(opc)) {
                return ConditionWalk.unresolved("bool_compose");
            }
            if (COMPARISON_OPS.contains(opc)) {
                Varnode a = d.getInput(0);
                Varnode b = d.getInput(1);
                if (isBoolComposition(a) || isBoolComposition(b)) {
                    // Empirical gate_bool shape:
                    // INT_NOTEQUAL(INT_AND(INT_EQUAL(a,X),flag),0) -- the outer
                    // compare's own operand is a bool-combinator composing two
                    // comparison-shaped values, so this is a composed
                    // condition, not a plain equality gate. (NOT the same as
                    // an arithmetic AND/OR/XOR over ordinary values, e.g.
                    // Ghidra 12.1.3's own `a*2==X` -> `(sext(a) &
                    // 0x7fffffffffffffff) == X` simplification -- de-risk
                    // step 2, gate_arith -- which isBoolComposition correctly
                    // does not flag.)
                    return ConditionWalk.unresolved("bool_compose");
                }
                int fanout = 0;
                Iterator<PcodeOp> desc = cur.getDescendants();
                while (desc.hasNext()) {
                    desc.next();
                    fanout++;
                }
                if (fanout > 1) {
                    return ConditionWalk.unresolved("bool_fanout");
                }
                int[] arr = new int[peeled.size()];
                for (int i = 0; i < arr.length; i++) {
                    arr[i] = peeled.get(i);
                }
                return ConditionWalk.resolved(resolveConditionFromPeeled(opc, arr), d);
            }
            return ConditionWalk.unresolved("bool_fanout");
        }
        return ConditionWalk.unresolved("bool_fanout");
    }

    /**
     * BFS reachability from entry to any sinkBlocks member, skipping any
     * out-edge whose target equals cutEdge.get(sourceBlock). An empty cutEdge
     * map is the uncut-graph baseline check (Step 0).
     */
    private boolean reachable(PcodeBlock entry, Set<PcodeBlock> sinkBlocks,
            Map<PcodeBlock, PcodeBlock> cutEdge) {
        Set<PcodeBlock> seen = new HashSet<>();
        Deque<PcodeBlock> stack = new ArrayDeque<>();
        stack.push(entry);
        seen.add(entry);
        while (!stack.isEmpty()) {
            PcodeBlock b = stack.pop();
            if (sinkBlocks.contains(b)) {
                return true;
            }
            PcodeBlock cutTarget = cutEdge.get(b);
            int n = b.getOutSize();
            for (int i = 0; i < n; i++) {
                PcodeBlock s = b.getOut(i);
                if (cutTarget != null && cutTarget.equals(s)) {
                    continue;
                }
                if (seen.add(s)) {
                    stack.push(s);
                }
            }
        }
        return false;
    }

    /**
     * §2.2 Step 1's per-branch edge-cut test: cut each out-edge of cb's block
     * in turn; if exactly one cut disconnects every sink, that is the required
     * edge (true/false). Returns null when neither (or both) cuts disconnect
     * -- the branch does not individually gate, and is carried to Step 2.
     */
    private Boolean requiredEdgeIsTrue(PcodeOp cb, PcodeBlock entry, Set<PcodeBlock> sinkBlocks) {
        PcodeBlock blk = cb.getParent();
        PcodeBlock trueTarget = blk.getTrueOut();
        PcodeBlock falseTarget = blk.getFalseOut();
        Map<PcodeBlock, PcodeBlock> cutTrue = Collections.singletonMap(blk, trueTarget);
        Map<PcodeBlock, PcodeBlock> cutFalse = Collections.singletonMap(blk, falseTarget);
        boolean trueCutDisconnects = !reachable(entry, sinkBlocks, cutTrue);
        boolean falseCutDisconnects = !reachable(entry, sinkBlocks, cutFalse);
        if (trueCutDisconnects == falseCutDisconnects) {
            return null;
        }
        return trueCutDisconnects;
    }

    /**
     * §2.2 Step 2 backward must-reach fixed point over the pruned graph:
     * MustReachSink = sinkBlocks ∪ { v | succ(v)≠∅ ∧ ∀ s∈succ(v): s∈MustReachSink }.
     */
    private Set<PcodeBlock> computeMustReachSink(List<PcodeBlockBasic> allBlocks,
            Set<PcodeBlock> sinkBlocks, Map<PcodeBlock, PcodeBlock> cutEdge) {
        Set<PcodeBlock> must = new HashSet<>(sinkBlocks);
        boolean changed = true;
        while (changed) {
            changed = false;
            for (PcodeBlockBasic v : allBlocks) {
                if (must.contains(v)) {
                    continue;
                }
                PcodeBlock cutTarget = cutEdge.get(v);
                int n = v.getOutSize();
                int liveSucc = 0;
                boolean allIn = true;
                for (int i = 0; i < n; i++) {
                    PcodeBlock s = v.getOut(i);
                    if (cutTarget != null && cutTarget.equals(s)) {
                        continue;
                    }
                    liveSucc++;
                    if (!must.contains(s)) {
                        allIn = false;
                    }
                }
                if (liveSucc > 0 && allIn) {
                    must.add(v);
                    changed = true;
                }
            }
        }
        return must;
    }

    /** A pinnable-equality branch collected for Step 2's domain/pruning. */
    private static final class EnumerableBranch {
        final PcodeOp cbranch;
        final ResolvedComparison rc;
        final int slot;
        final long constValue;   // normalized to the param's source width
        final int srcWidthBits;

        EnumerableBranch(PcodeOp cbranch, ResolvedComparison rc, int slot,
                long constValue, int srcWidthBits) {
            this.cbranch = cbranch;
            this.rc = rc;
            this.slot = slot;
            this.constValue = constValue;
            this.srcWidthBits = srcWidthBits;
        }
    }

    /** §2.2 Step 2 domain element: a concrete value, or the bottom sentinel. */
    private static final class DomainValue {
        final boolean bottom;
        final long value;

        private DomainValue(boolean bottom, long value) {
            this.bottom = bottom;
            this.value = value;
        }

        static DomainValue of(long v) {
            return new DomainValue(false, v);
        }

        static final DomainValue BOTTOM = new DomainValue(true, 0);
    }

    /** §2.4 one emitted required argument, fully provenanced. */
    private static final class RequiredArg {
        int position;
        long value;
        int slot;
        int widthBits;
        int srcWidthBits;
        String reg;           // null iff the formal's storage disqualifies it (abi_class)
        int op;                // PcodeOp.INT_EQUAL or INT_NOTEQUAL
        long opAddr;
        List<Long> sinkAddrs;
        List<Integer> transform;
    }

    /** The extractor's per-function requiredness verdict. */
    private static final class ArgsResult {
        final String status;
        final String reason;
        final List<RequiredArg> args;

        private ArgsResult(String status, String reason, List<RequiredArg> args) {
            this.status = status;
            this.reason = reason;
            this.args = args;
        }

        static ArgsResult known(List<RequiredArg> args) {
            return new ArgsResult(KNOWN, null, args);
        }

        static ArgsResult unknown(String reason) {
            return new ArgsResult(UNKNOWN_STATUS, reason, Collections.<RequiredArg>emptyList());
        }
    }

    private static String higherPrecedence(String a, String b) {
        int ia = REASON_PRECEDENCE.indexOf(a);
        int ib = REASON_PRECEDENCE.indexOf(b);
        return ia <= ib ? a : b;
    }

    private static int paramSourceWidthBits(HighFunction hf, int slot) {
        HighParam hp = hf.getLocalSymbolMap().getParam(slot);
        return hp == null ? 0 : 8 * hp.getSize();
    }

    private static long maskTo(long v, int widthBits) {
        if (widthBits <= 0 || widthBits >= 64) {
            return v;
        }
        return v & ((1L << widthBits) - 1);
    }

    /**
     * §2.4/§2.2: mask the raw compared constant to the comparison width, then
     * (when the comparison is wider than the formal's own storage -- a
     * ZEXT/SEXT'd compare) further truncate to the source width, so a
     * sign-extended constant de-duplicates against its source-width pattern.
     */
    private static long normalizeConst(long raw, int comparisonWidthBits, int srcWidthBits) {
        long atCompareWidth = maskTo(raw, comparisonWidthBits);
        if (srcWidthBits <= 0 || srcWidthBits >= comparisonWidthBits) {
            return atCompareWidth;
        }
        return maskTo(atCompareWidth, srcWidthBits);
    }

    /** §2.4 opcode -> canonical name string (never Ghidra's pretty mnemonic). */
    private static String opcodeName(int opc) {
        switch (opc) {
            case PcodeOp.COPY: return "COPY";
            case PcodeOp.CAST: return "CAST";
            case PcodeOp.INT_ZEXT: return "INT_ZEXT";
            case PcodeOp.INT_SEXT: return "INT_SEXT";
            case PcodeOp.BOOL_NEGATE: return "BOOL_NEGATE";
            case PcodeOp.INT_EQUAL: return "INT_EQUAL";
            case PcodeOp.INT_NOTEQUAL: return "INT_NOTEQUAL";
            default: return "OPC_" + opc;
        }
    }

    /**
     * §3 register derivation for an emitted arg: null unless the formal's
     * storage is a single simple integer SysV argument register (the three
     * abi_class sub-cases -- null/stack, compound, non-integer -- all collapse
     * to reg==null here).
     */
    private static String emittedArgRegister(HighFunction hf, int slot) {
        HighParam hp = hf.getLocalSymbolMap().getParam(slot);
        if (hp == null) {
            return null;
        }
        VariableStorage st = hp.getSymbol().getStorage();
        boolean simpleReg = st.isRegisterStorage() && !st.isCompoundStorage()
                && st.getVarnodeCount() == 1;
        if (!simpleReg) {
            return null;
        }
        Register r = st.getRegister();
        Register br = (r != null) ? r.getBaseRegister() : null;
        if (br == null || !SYSV_INT_BASE_REGS.contains(br.getName().toUpperCase())) {
            return null;
        }
        return br.getName().toLowerCase();
    }

    private RequiredArg buildRequiredArg(HighFunction hf, PcodeOp cmpOp, ResolvedComparison rc,
            SlotInfo paramSide, long value, List<Long> allSinkAddrs) {
        RequiredArg ra = new RequiredArg();
        ra.slot = paramSide.slot;
        ra.position = paramSide.slot + 1;
        ra.value = value;
        ra.widthBits = paramSide.widthBits;
        ra.srcWidthBits = paramSourceWidthBits(hf, paramSide.slot);
        ra.op = rc.cmpOpcode;
        ra.opAddr = cmpOp.getSeqnum().getTarget().getOffset();
        ra.transform = new ArrayList<>(paramSide.transform);
        ra.sinkAddrs = new ArrayList<>(allSinkAddrs);
        ra.reg = emittedArgRegister(hf, paramSide.slot);
        return ra;
    }

    /**
     * §2.2 Step 2: build the interesting-value domain for every free param,
     * enumerate the cartesian product (capped at ENUM_CAP), and for each
     * assignment test whether the sink becomes avoidable under the pruned CFG.
     * Returns true iff some assignment avoids the sink (-> unresolved_gate).
     */
    private boolean runStep2(List<PcodeBlockBasic> allBlocks, PcodeBlock entry,
            Set<PcodeBlock> sinkBlocks, List<EnumerableBranch> allEnumerable,
            Map<Integer, Long> pinnedBySlot) {
        Map<Integer, Set<Long>> domainConsts = new LinkedHashMap<>();
        Map<Integer, Integer> slotSrcWidth = new LinkedHashMap<>();
        for (EnumerableBranch eb : allEnumerable) {
            if (pinnedBySlot.containsKey(eb.slot)) {
                continue;
            }
            Set<Long> set = domainConsts.get(eb.slot);
            if (set == null) {
                set = new LinkedHashSet<>();
                domainConsts.put(eb.slot, set);
            }
            set.add(eb.constValue);
            slotSrcWidth.put(eb.slot, eb.srcWidthBits);
        }

        List<Integer> freeSlots = new ArrayList<>(domainConsts.keySet());
        List<List<DomainValue>> domains = new ArrayList<>();
        long product = 1;
        for (Integer slot : freeSlots) {
            Set<Long> consts = domainConsts.get(slot);
            int widthBits = slotSrcWidth.get(slot);
            List<DomainValue> dom = new ArrayList<>();
            for (Long c : consts) {
                dom.add(DomainValue.of(c));
            }
            boolean addBottom = (widthBits > 12) || (consts.size() < (1L << widthBits));
            if (addBottom) {
                dom.add(DomainValue.BOTTOM);
            }
            domains.add(dom);
            product *= dom.size();
            if (product > ENUM_CAP) {
                return true; // fail closed: treat as sink-avoidable -> unresolved_gate
            }
        }

        List<Map<Integer, DomainValue>> assignments = new ArrayList<>();
        assignments.add(new HashMap<Integer, DomainValue>());
        for (int i = 0; i < freeSlots.size(); i++) {
            int slot = freeSlots.get(i);
            List<DomainValue> dom = domains.get(i);
            List<Map<Integer, DomainValue>> next = new ArrayList<>();
            for (Map<Integer, DomainValue> partial : assignments) {
                for (DomainValue dv : dom) {
                    Map<Integer, DomainValue> m = new HashMap<>(partial);
                    m.put(slot, dv);
                    next.add(m);
                }
            }
            assignments = next;
        }

        for (Map<Integer, DomainValue> sigma : assignments) {
            if (sinkAvoidableUnder(sigma, allEnumerable, pinnedBySlot, allBlocks, entry, sinkBlocks)) {
                return true;
            }
        }
        return false;
    }

    private boolean sinkAvoidableUnder(Map<Integer, DomainValue> sigma,
            List<EnumerableBranch> allEnumerable, Map<Integer, Long> pinnedBySlot,
            List<PcodeBlockBasic> allBlocks, PcodeBlock entry, Set<PcodeBlock> sinkBlocks) {
        Map<PcodeBlock, PcodeBlock> cut = new HashMap<>();
        for (EnumerableBranch eb : allEnumerable) {
            boolean eq;
            if (pinnedBySlot.containsKey(eb.slot)) {
                eq = pinnedBySlot.get(eb.slot).longValue() == eb.constValue;
            } else {
                DomainValue dv = sigma.get(eb.slot);
                eq = dv != null && !dv.bottom && dv.value == eb.constValue;
            }
            boolean determinedEdgeIsTrue = step2SelectedEdgeIsTrue(eb.rc, eq);
            PcodeBlock blk = eb.cbranch.getParent();
            PcodeBlock notTaken = determinedEdgeIsTrue ? blk.getFalseOut() : blk.getTrueOut();
            cut.put(blk, notTaken);
        }
        Set<PcodeBlock> must = computeMustReachSink(allBlocks, sinkBlocks, cut);
        return !must.contains(entry);
    }

    /**
     * §2/§3: the W-2 requiredness pass for one function's HighFunction. Not
     * itself wrapped in try/catch -- the caller (analyze()) does that, per
     * design §3's failure-isolation requirement (a thrown exception here must
     * taint only this function's args_status, never the W-1 decompile count).
     */
    private ArgsResult extractRequiredArgs(HighFunction hf, List<PcodeOp> constStringSinkOps) {
        if (constStringSinkOps.isEmpty()) {
            return ArgsResult.known(Collections.<RequiredArg>emptyList());
        }
        List<PcodeBlockBasic> allBlocks = hf.getBasicBlocks();
        if (allBlocks.isEmpty()) {
            return ArgsResult.unknown("irreducible_cflow");
        }
        PcodeBlock entry = allBlocks.get(0);
        Set<PcodeBlock> sinkBlocks = new HashSet<>();
        List<Long> allSinkAddrs = new ArrayList<>();
        for (PcodeOp op : constStringSinkOps) {
            sinkBlocks.add(op.getParent());
            allSinkAddrs.add(op.getSeqnum().getTarget().getOffset());
        }

        // Step 0 -- baseline reachability in the uncut graph.
        if (!reachable(entry, sinkBlocks, Collections.<PcodeBlock, PcodeBlock>emptyMap())) {
            return ArgsResult.unknown("irreducible_cflow");
        }

        List<PcodeOp> cbranches = new ArrayList<>();
        Iterator<PcodeOpAST> opIt = hf.getPcodeOps();
        while (opIt.hasNext()) {
            PcodeOpAST op = opIt.next();
            if (op.getOpcode() == PcodeOp.CBRANCH) {
                cbranches.add(op);
            }
        }

        Map<Integer, Long> pinnedBySlot = new LinkedHashMap<>();
        Map<Integer, RequiredArg> emittedBySlot = new LinkedHashMap<>();
        List<EnumerableBranch> allEnumerable = new ArrayList<>();
        Set<String> taints = new HashSet<>();

        for (PcodeOp cb : cbranches) {
            ConditionWalk cw = walkCondition(cb.getInput(1));
            boolean paramDependent;
            int role = ROLE_NON_GATE;
            SlotInfo s0 = null;
            SlotInfo s1 = null;

            if (cw.unresolvedCause == null) {
                Varnode in0 = cw.terminalCmpOp.getInput(0);
                Varnode in1 = cw.terminalCmpOp.getInput(1);
                s0 = traceParamSlot(in0, in1, TRACE_DEPTH);
                s1 = traceParamSlot(in1, in0, TRACE_DEPTH);
                role = classifyCompare(s0, s1, in0.isConstant(), in1.isConstant());
                paramDependent = role != ROLE_NON_GATE;
                if (role == ROLE_PINNABLE && EQUALITY_OPS.contains(cw.rc.cmpOpcode)) {
                    SlotInfo paramSide = (s0.kind == SlotKind.PARAM) ? s0 : s1;
                    Varnode constSide = (s0.kind == SlotKind.PARAM) ? in1 : in0;
                    int srcWidthBits = paramSourceWidthBits(hf, paramSide.slot);
                    long normConst = normalizeConst(
                            constSide.getOffset(), paramSide.widthBits, srcWidthBits);
                    allEnumerable.add(new EnumerableBranch(
                            cb, cw.rc, paramSide.slot, normConst, srcWidthBits));
                }
            } else {
                paramDependent = true; // an unresolved condition is still carried through
            }

            if (!paramDependent) {
                continue; // uncontrolled: left adversarial automatically in Step 2
            }

            Boolean requiredEdgeIsTrue = requiredEdgeIsTrue(cb, entry, sinkBlocks);
            if (requiredEdgeIsTrue == null) {
                continue; // does not individually gate; carried to Step 2
            }

            if (cw.unresolvedCause != null) {
                taints.add(cw.unresolvedCause);
                continue;
            }
            if (role == ROLE_AMBIGUOUS_PARAM) {
                taints.add("ambiguous_gate");
                continue;
            }
            if (role == ROLE_NONCONST_PARAM) {
                taints.add("nonconst_gate");
                continue;
            }
            // role == ROLE_PINNABLE
            int cmpOp = cw.rc.cmpOpcode;
            if (!EQUALITY_OPS.contains(cmpOp)) {
                taints.add("relational_gate");
                continue;
            }
            boolean emits = step1EmitsEquality(cw.rc, requiredEdgeIsTrue.booleanValue());
            if (!emits) {
                taints.add("avoidance_gate");
                continue;
            }
            SlotInfo paramSide = (s0.kind == SlotKind.PARAM) ? s0 : s1;
            Varnode constSide = (s0.kind == SlotKind.PARAM) ? cw.terminalCmpOp.getInput(1)
                    : cw.terminalCmpOp.getInput(0);
            int srcWidthBits = paramSourceWidthBits(hf, paramSide.slot);
            // Two distinct normalizations (design §2.2 vs §2.4): pinKey lives in the
            // param's source-width space (so a direct compare and a ZEXT/SEXT'd
            // compare of the SAME slot are recognized as the same/different
            // value for conflict detection and Step 2's D(p) domain), while the
            // SERIALIZED required-arg value is masked only to the comparison
            // width, per §2.4's "value is the constant masked to the
            // comparison width" -- the two differ whenever srcWidthBits <
            // paramSide.widthBits (an extended compare).
            long pinKey = normalizeConst(constSide.getOffset(), paramSide.widthBits, srcWidthBits);
            long emitValue = maskTo(constSide.getOffset(), paramSide.widthBits);
            int slot = paramSide.slot;
            Long existing = pinnedBySlot.get(slot);
            if (existing != null && existing.longValue() != pinKey) {
                taints.add("conflict");
                continue;
            }
            pinnedBySlot.put(slot, pinKey);
            if (!emittedBySlot.containsKey(slot)) {
                emittedBySlot.put(slot,
                        buildRequiredArg(hf, cw.terminalCmpOp, cw.rc, paramSide, emitValue, allSinkAddrs));
            }
        }

        if (!taints.isEmpty()) {
            String reason = null;
            for (String t : taints) {
                reason = (reason == null) ? t : higherPrecedence(reason, t);
            }
            return ArgsResult.unknown(reason);
        }

        boolean avoided = runStep2(allBlocks, entry, sinkBlocks, allEnumerable, pinnedBySlot);
        if (avoided) {
            return ArgsResult.unknown("unresolved_gate");
        }

        List<RequiredArg> finalArgs = new ArrayList<>(emittedBySlot.values());
        for (RequiredArg ra : finalArgs) {
            if (ra.reg == null) {
                return ArgsResult.unknown("abi_class");
            }
        }
        Collections.sort(finalArgs, new Comparator<RequiredArg>() {
            @Override
            public int compare(RequiredArg a, RequiredArg b) {
                return Integer.compare(a.position, b.position);
            }
        });
        return ArgsResult.known(finalArgs);
    }

    /** Per-function evidence, serialized into one record. */
    private static final class Evidence {
        long address;
        String name;
        boolean hasRead;
        boolean hasStdout;
        boolean unreferenced;
        final List<String> sinkApis = new ArrayList<>();
        final List<Trace> sinkTargets = new ArrayList<>();
        String argsStatus = KNOWN;
        String argsReason;
        List<RequiredArg> requiredArgs = Collections.<RequiredArg>emptyList();
    }

    /**
     * Collect evidence for one function. Returns null when the body could not be
     * decompiled, so the caller counts it as a failure (the COMPLETE invariant
     * forbids a partial pass from passing as complete).
     */
    private Evidence analyze(Function f) {
        HighFunction hf = highOf(f);
        if (hf == null) {
            return null;
        }
        Evidence ev = new Evidence();
        ev.address = f.getEntryPoint().getOffset();
        ev.name = f.getName();
        ev.unreferenced = !hasIncomingCall(f);

        List<PcodeOp> constStringSinkOps = new ArrayList<>();
        Iterator<PcodeOpAST> it = hf.getPcodeOps();
        while (it.hasNext()) {
            PcodeOpAST op = it.next();
            if (!isCallOp(op)) {
                continue;
            }
            Set<String> canon = new HashSet<>();
            for (String raw : calleeNames(op)) {
                canon.add(canonicalImport(raw));
            }
            for (String api : canon) {
                if (READ_FAMILY.contains(api)) {
                    ev.hasRead = true;
                }
                if (STDOUT_FAMILY.contains(api)) {
                    ev.hasStdout = true;
                }
            }
            String sinkApi = null;
            for (String api : canon) {
                if (EXEC_FAMILY.contains(api) || FILE_OPEN_FAMILY.contains(api)) {
                    sinkApi = api;
                    break;
                }
            }
            if (sinkApi == null) {
                continue;
            }
            int idx = pathInputIndex(sinkApi);
            Trace target = op.getNumInputs() > idx
                    ? traceTarget(op.getInput(idx), TRACE_DEPTH, new HashSet<Varnode>())
                    : Trace.UNK;
            ev.sinkApis.add(sinkApi);
            ev.sinkTargets.add(target);
            if (CONST_STRING.equals(target.kind)) {
                constStringSinkOps.add(op);
            }
        }

        ArgsResult argsResult;
        try {
            argsResult = extractRequiredArgs(hf, constStringSinkOps);
        } catch (Exception e) {
            argsResult = ArgsResult.unknown("analysis_exception");
        }
        ev.argsStatus = argsResult.status;
        ev.argsReason = argsResult.reason;
        ev.requiredArgs = argsResult.args;
        return ev;
    }

    private static void appendTrace(StringBuilder sb, Trace t) {
        sb.append("{\"kind\":\"").append(esc(t.kind)).append("\",\"address\":");
        if (t.address == null) {
            sb.append("null");
        } else {
            sb.append(Long.toUnsignedString(t.address));
        }
        sb.append(",\"value\":");
        if (t.value == null) {
            sb.append("null");
        } else {
            sb.append('"').append(esc(t.value)).append('"');
        }
        sb.append('}');
    }

    private static void appendRequiredArg(StringBuilder sb, RequiredArg a) {
        sb.append("{\"position\":").append(a.position)
          .append(",\"value\":").append(a.value)
          .append(",\"slot\":").append(a.slot)
          .append(",\"width_bits\":").append(a.widthBits)
          .append(",\"src_width_bits\":").append(a.srcWidthBits)
          .append(",\"terminal\":\"HighParam\"")
          .append(",\"reg\":");
        if (a.reg == null) {
            sb.append("null");
        } else {
            sb.append('"').append(esc(a.reg)).append('"');
        }
        sb.append(",\"op\":\"").append(opcodeName(a.op)).append('"')
          .append(",\"op_addr\":").append(Long.toUnsignedString(a.opAddr))
          .append(",\"sink_addrs\":[");
        for (int i = 0; i < a.sinkAddrs.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(Long.toUnsignedString(a.sinkAddrs.get(i)));
        }
        sb.append("],\"transform\":[");
        for (int i = 0; i < a.transform.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append('"').append(opcodeName(a.transform.get(i))).append('"');
        }
        sb.append("]}");
    }

    private static void appendRecord(StringBuilder sb, Evidence ev) {
        sb.append("{\"address\":").append(Long.toUnsignedString(ev.address))
          .append(",\"name\":\"").append(esc(ev.name)).append("\",\"sinks\":[");
        for (int i = 0; i < ev.sinkApis.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"api\":\"").append(esc(ev.sinkApis.get(i)))
              .append("\",\"target\":");
            appendTrace(sb, ev.sinkTargets.get(i));
            sb.append('}');
        }
        sb.append("],\"has_read\":").append(ev.hasRead)
          .append(",\"has_stdout_output\":").append(ev.hasStdout)
          .append(",\"unreferenced\":").append(ev.unreferenced)
          .append(",\"args_status\":\"").append(esc(ev.argsStatus)).append('"')
          .append(",\"args_reason\":");
        if (ev.argsReason == null) {
            sb.append("null");
        } else {
            sb.append('"').append(esc(ev.argsReason)).append('"');
        }
        sb.append(",\"required_args\":[");
        for (int i = 0; i < ev.requiredArgs.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            appendRequiredArg(sb, ev.requiredArgs.get(i));
        }
        sb.append("]}");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = (args.length > 0 && args[0] != null && !args[0].isEmpty())
                ? args[0] : "supwngo_payoff.json";
        // args[1] (entry RVA) and args[2] (format) are accepted for parity with
        // SupwngoDecompile and future use; W-1 reachability is reference-based.
        long backendBase = currentProgram.getImageBase().getOffset();

        int enumerated = 0;
        int analyzed = 0;
        int failed = 0;
        List<Evidence> records = new ArrayList<>();

        decomp = new DecompInterface();
        try {
            decomp.openProgram(currentProgram);
            FunctionManager fm = currentProgram.getFunctionManager();
            FunctionIterator fit = fm.getFunctions(true);
            while (fit.hasNext()) {
                Function f = fit.next();
                if (!isRealFunction(f)) {
                    continue;
                }
                enumerated++;
                Evidence ev;
                try {
                    ev = analyze(f);
                } catch (Exception e) {
                    ev = null;
                }
                if (ev == null) {
                    failed++;
                    printerr("payoff: decompile failed for " + f.getName());
                } else {
                    analyzed++;
                    records.add(ev);
                }
            }
        } finally {
            decomp.dispose();
            StringBuilder sb = new StringBuilder();
            sb.append("{\"script_version\":\"").append(esc(SCRIPT_VERSION))
              .append("\",\"backend_base\":").append(Long.toUnsignedString(backendBase))
              .append(",\"enumerated\":").append(enumerated)
              .append(",\"analyzed\":").append(analyzed)
              .append(",\"failed\":").append(failed)
              .append(",\"records\":[");
            for (int i = 0; i < records.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                appendRecord(sb, records.get(i));
            }
            sb.append("]}");
            OutputStreamWriter w = new OutputStreamWriter(
                    new FileOutputStream(outPath), StandardCharsets.UTF_8);
            try {
                w.write(sb.toString());
            } finally {
                w.close();
            }
            println("SupwngoPayoff wrote " + outPath + " (" + analyzed + "/"
                    + enumerated + " analyzed, " + failed + " failed)");
        }
    }
}
