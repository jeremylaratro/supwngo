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
// Output envelope (a single UTF-8 JSON OBJECT written to arg0 so the caller can
// tell "ran, analyzed everything, found nothing" from "never ran" and from
// "ran but a function failed"):
//   {
//     "script_version": "w1.1",
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
//        "has_read": <bool>, "has_stdout_output": <bool>, "unreferenced": <bool>
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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class SupwngoPayoff extends GhidraScript {

    private static final String SCRIPT_VERSION = "w1.1";

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

    private DecompInterface decomp;

    private static Set<String> setOf(String... names) {
        return new HashSet<>(Arrays.asList(names));
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

    /** Per-function evidence, serialized into one record. */
    private static final class Evidence {
        long address;
        String name;
        boolean hasRead;
        boolean hasStdout;
        boolean unreferenced;
        final List<String> sinkApis = new ArrayList<>();
        final List<Trace> sinkTargets = new ArrayList<>();
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
        }
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
          .append(",\"unreferenced\":").append(ev.unreferenced).append('}');
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
