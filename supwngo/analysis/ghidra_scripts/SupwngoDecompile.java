// SupwngoDecompile.java - headless Ghidra decompilation for supwngo.
//
// Driven by supwngo.analysis.decompile.Decompiler._decompile_ghidra via
// analyzeHeadless. This file MUST live in its own near-empty directory: Ghidra
// enumerates every file in each -scriptPath directory to classify scripts, so a
// crowded directory (e.g. /tmp) hangs postScript resolution. A .java script is
// used deliberately -- Ghidra 12.x without PyGhidra cannot run .py scripts.
//
// Script args (positional, always all five):
//   arg0  tagged target selector
//   arg1  output JSON path
//   arg2  the file's link-time base (hex), or "none"
//   arg3  entry point as an offset from that base (hex RVA), or "none"
//   arg4  file format: "elf", "pe" or "unknown"
//
// Selector (arg0):
//   "name:<fname>"  -> first global function with that name       (selected_by "name")
//   "addr:<0xNN|NN>" -> function whose entry point is that address (selected_by "addr")
//   ""/"all"         -> the default function, below
// A tagged selector is used so a function literally named "0x..." or "123" is
// still selectable by name, and so name-vs-address precedence is explicit.
//
// Address convention: an "addr:" selector is in the *file's* convention (the
// one objdump/nm print). Ghidra loads a program at its own image base, so the
// selector is mapped with  ghidra = image_base + (selector - arg2)  before the
// lookup. The output reports Ghidra's own address and its image base
// ("backend_base"); the caller maps the address back with the same two bases.
//
// Default function (empty selector). The entry function is image_base + arg3
// (Ghidra 12.1.3 has no Program.getEntryPoint()). Orders, first match wins, and
// the result says which one matched in "selected_by":
//   ELF  1. a global function named main                      "symbol"
//        2. the first argument of the entry function's call to
//           __libc_start_main, when it is a constant address   "libc_start_main_arg"
//        3. the entry function, when it makes no such call     "entry"
//        4. the first non-thunk, non-external function reached
//           breadth-first from the entry function              "first_reachable"
//   PE   1. a global function named main                      "symbol"
//        2. the function whose result the CRT start passes to
//           exit(), found within a bounded call depth          "mingw_crt_main_arg"
//        3. the entry function (the CRT start itself)          "entry"
// first_reachable is not used for PE: a breadth-first walk through CRT
// initialisation is not a main detector. With no entry function nothing is
// selected. Prelinked ELF is not supported.
//
// Always writes a UTF-8 JSON array (possibly empty "[]") to arg1 so the caller
// can distinguish "ran but found nothing" from "never ran".
//@category Supwngo

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.pcode.HighFunction;
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
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class SupwngoDecompile extends GhidraScript {

    /** Minimal RFC-8259 string escaping (no external JSON library on the path). */
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

    /** A selected function and how it was selected. */
    private static final class Pick {
        final Function f;
        final String by;

        Pick(Function f, String by) {
            this.f = f;
            this.by = by;
        }
    }

    /** Opened once in run(); shared by the selection analysis and the output. */
    private DecompInterface decomp;

    /** Longest call depth searched below the entry function, and node cap. */
    private static final int MAX_DEPTH = 3;
    private static final int MAX_NODES = 32;

    /** Names under which a libc start routine is recognised. */
    private static boolean isLibcStart(String name) {
        return "__libc_start_main".equals(name)
                || "__libc_start_main_impl".equals(name);
    }

    /**
     * Resolve the function to decompile from the tagged arg0 selector. fileBase
     * is the file's link-time base (null if unknown); backendBase is Ghidra's
     * image base for the loaded program.
     */
    private Pick resolve(String selector, Long fileBase, long backendBase,
                         Long entryRva, String format) throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();

        if (selector != null && selector.startsWith("addr:")) {
            String a = selector.substring("addr:".length()).trim();
            try {
                long off = parseOffset(a);
                if (fileBase != null) {
                    off = backendBase + (off - fileBase);
                }
                Address addr = currentProgram.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(off);
                Function f = fm.getFunctionAt(addr);
                return f == null ? null : new Pick(f, "addr");
            } catch (Exception e) {
                return null;
            }
        }

        if (selector != null && selector.startsWith("name:")) {
            String name = selector.substring("name:".length());
            List<Function> named = getGlobalFunctions(name);
            if (named != null && !named.isEmpty()) {
                return new Pick(named.get(0), "name");
            }
            return null;
        }

        return resolveDefault(backendBase, entryRva, format);
    }

    /** The default function: see the order in the header comment. */
    private Pick resolveDefault(long backendBase, Long entryRva, String format)
            throws Exception {
        List<Function> mains = getGlobalFunctions("main");
        if (mains != null && !mains.isEmpty()) {
            return new Pick(mains.get(0), "symbol");
        }

        Function entry = entryFunction(backendBase, entryRva);
        if (entry == null) {
            return null;
        }

        if ("pe".equals(format)) {
            Function m = mainFromExitResult(entry);
            return m != null ? new Pick(m, "mingw_crt_main_arg")
                             : new Pick(entry, "entry");
        }

        boolean[] sawStart = {false};
        Function m = mainFromLibcStart(entry, sawStart);
        if (m != null) {
            return new Pick(m, "libc_start_main_arg");
        }
        if (!sawStart[0]) {
            return new Pick(entry, "entry");
        }
        List<Function> reach = reachableFrom(entry, MAX_DEPTH, MAX_NODES, false);
        return reach.isEmpty() ? new Pick(entry, "entry")
                               : new Pick(reach.get(0), "first_reachable");
    }

    /** The function at image_base + entry RVA, or null. */
    private Function entryFunction(long backendBase, Long entryRva) {
        if (entryRva == null) {
            return null;
        }
        try {
            Address ea = currentProgram.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(backendBase + entryRva);
            FunctionManager fm = currentProgram.getFunctionManager();
            Function f = fm.getFunctionAt(ea);
            return f != null ? f : fm.getFunctionContaining(ea);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Does the loader agree that the entry point is where arg3 says? "ok" when
     * Ghidra lists that address as an external entry point; otherwise a note
     * naming what it does list, so a mismatch is recorded rather than hidden.
     */
    private String entryCheck(long backendBase, Long entryRva) {
        if (entryRva == null) {
            return "no entry offset";
        }
        try {
            Address ea = currentProgram.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(backendBase + entryRva);
            if (currentProgram.getSymbolTable().isExternalEntryPoint(ea)) {
                return "ok";
            }
            StringBuilder b = new StringBuilder("mismatch: loader entry points [");
            Iterator<Address> it =
                    currentProgram.getSymbolTable().getExternalEntryPointIterator();
            while (it.hasNext()) {
                b.append(it.next()).append(' ');
            }
            return b.append("] do not include ").append(ea).toString();
        } catch (Exception e) {
            return "entry check failed: " + e;
        }
    }

    private HighFunction highOf(Function f) {
        DecompileResults res = decomp.decompileFunction(f, 30, new ConsoleTaskMonitor());
        return res == null ? null : res.getHighFunction();
    }

    /**
     * Names a CALL/CALLIND resolves to: the callee and what it thunks to, plus
     * the symbols and external labels the call site (and the GOT/IAT slot it
     * goes through) refer to. An indirect call through a dynamic import has no
     * callee function in the program, only these references.
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

    /** A code address held by a Varnode: a constant, or PTRSUB(0, constant). */
    private Address constantAddress(Varnode v) {
        try {
            for (int i = 0; i < 6 && v != null; i++) {
                if (v.isConstant()) {
                    return currentProgram.getAddressFactory().getDefaultAddressSpace()
                            .getAddress(v.getOffset());
                }
                PcodeOp d = v.getDef();
                if (d == null) {
                    return null;
                }
                int opc = d.getOpcode();
                if (opc == PcodeOp.PTRSUB && d.getInput(0).isConstant()
                        && d.getInput(0).getOffset() == 0 && d.getInput(1).isConstant()) {
                    return currentProgram.getAddressFactory().getDefaultAddressSpace()
                            .getAddress(d.getInput(1).getOffset());
                }
                if (opc == PcodeOp.COPY || opc == PcodeOp.CAST
                        || opc == PcodeOp.INT_ZEXT) {
                    v = d.getInput(0);
                    continue;
                }
                return null;
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    private static boolean isCallOp(PcodeOp op) {
        return op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND;
    }

    private static List<PcodeOpAST> callOps(HighFunction hf) {
        List<PcodeOpAST> out = new ArrayList<>();
        if (hf != null) {
            Iterator<PcodeOpAST> it = hf.getPcodeOps();
            while (it.hasNext()) {
                PcodeOpAST op = it.next();
                if (isCallOp(op)) {
                    out.add(op);
                }
            }
        }
        return out;
    }

    private boolean isRealFunction(Function f) {
        return f != null && !f.isThunk() && !f.isExternal();
    }

    /**
     * Input 1 of the entry function's call to __libc_start_main, when that is a
     * constant address naming a real function. sawStart is set when the call is
     * there at all, constant argument or not.
     */
    private Function mainFromLibcStart(Function entry, boolean[] sawStart) {
        for (PcodeOpAST op : callOps(highOf(entry))) {
            boolean libc = false;
            for (String n : calleeNames(op)) {
                libc |= isLibcStart(n);
            }
            if (!libc) {
                continue;
            }
            sawStart[0] = true;
            if (op.getNumInputs() < 2) {
                continue;
            }
            Address a = constantAddress(op.getInput(1));
            if (a == null) {
                continue;
            }
            Function m = currentProgram.getFunctionManager().getFunctionAt(a);
            if (isRealFunction(m)) {
                return m;
            }
        }
        return null;
    }

    /**
     * The mingw CRT start ends with  mainret = main(argc, argv, envp);
     * exit(mainret). Search the entry function and its callees, to a bounded
     * depth, for an exit() call whose argument is the result of a direct call,
     * and return that callee.
     */
    private Function mainFromExitResult(Function entry) {
        for (Function f : reachableFrom(entry, MAX_DEPTH, MAX_NODES, true)) {
            for (PcodeOpAST op : callOps(highOf(f))) {
                if (op.getNumInputs() < 2 || !calleeNames(op).contains("exit")) {
                    continue;
                }
                Varnode v = op.getInput(1);
                for (int i = 0; i < 4 && v != null && v.getDef() != null; i++) {
                    PcodeOp d = v.getDef();
                    int opc = d.getOpcode();
                    if (opc == PcodeOp.CALL) {
                        Function m = currentProgram.getFunctionManager()
                                .getFunctionAt(d.getInput(0).getAddress());
                        if (isRealFunction(m) && !m.equals(f)) {
                            return m;
                        }
                        break;
                    }
                    if (opc == PcodeOp.SUBPIECE || opc == PcodeOp.CAST
                            || opc == PcodeOp.COPY || opc == PcodeOp.INT_ZEXT
                            || opc == PcodeOp.INT_SEXT) {
                        v = d.getInput(0);
                        continue;
                    }
                    break;
                }
            }
        }
        return null;
    }

    /**
     * Real (non-thunk, non-external) functions reachable from root by direct
     * calls, breadth-first, callees of one function taken in address order, to
     * maxDepth levels and at most maxNodes functions. root is included first
     * only when includeRoot is set.
     */
    private List<Function> reachableFrom(Function root, int maxDepth, int maxNodes,
                                         boolean includeRoot) {
        List<Function> order = new ArrayList<>();
        Set<Address> seen = new HashSet<>();
        ArrayDeque<Function> level = new ArrayDeque<>();
        seen.add(root.getEntryPoint());
        level.add(root);
        if (includeRoot) {
            order.add(root);
        }
        for (int depth = 0; depth < maxDepth && !level.isEmpty(); depth++) {
            ArrayDeque<Function> next = new ArrayDeque<>();
            for (Function f : level) {
                List<Function> callees = new ArrayList<>();
                for (Function c : f.getCalledFunctions(new ConsoleTaskMonitor())) {
                    if (isRealFunction(c)) {
                        callees.add(c);
                    }
                }
                Collections.sort(callees, new Comparator<Function>() {
                    @Override
                    public int compare(Function a, Function b) {
                        return a.getEntryPoint().compareTo(b.getEntryPoint());
                    }
                });
                for (Function c : callees) {
                    if (order.size() >= maxNodes) {
                        return order;
                    }
                    if (seen.add(c.getEntryPoint())) {
                        order.add(c);
                        next.add(c);
                    }
                }
            }
            level = next;
        }
        return order;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String selector = (args.length > 0 && args[0] != null) ? args[0] : "";
        String outPath = (args.length > 1 && args[1] != null && !args[1].isEmpty())
                ? args[1] : "supwngo_decompile.json";
        Long fileBase = args.length > 2 ? parseOffset(args[2]) : null;
        Long entryRva = args.length > 3 ? parseOffset(args[3]) : null;
        String format = args.length > 4 && args[4] != null ? args[4] : "unknown";
        long backendBase = currentProgram.getImageBase().getOffset();
        boolean isDefault = !selector.startsWith("addr:") && !selector.startsWith("name:");

        StringBuilder sb = new StringBuilder("[");
        decomp = new DecompInterface();

        try {
            decomp.openProgram(currentProgram);
            Pick pick = resolve(selector, fileBase, backendBase, entryRva, format);
            if (pick == null) {
                // Ghidra logs a script's printerr as "ERROR <script>.java> ...";
                // the Python side reports that line ahead of any other.
                printerr("no function matched the selector '"
                        + (selector.isEmpty() ? "default" : selector) + "'");
            } else {
                Function f = pick.f;
                DecompileResults res =
                        decomp.decompileFunction(f, 60, new ConsoleTaskMonitor());
                if (res != null && res.decompileCompleted()
                        && res.getDecompiledFunction() != null) {
                    String code = res.getDecompiledFunction().getC();
                    sb.append("{\"name\":\"").append(esc(f.getName()))
                      .append("\",\"address\":")
                      .append(Long.toUnsignedString(f.getEntryPoint().getOffset()))
                      .append(",\"backend_base\":")
                      .append(Long.toUnsignedString(backendBase))
                      .append(",\"selected_by\":\"").append(esc(pick.by))
                      .append("\",\"entry_check\":\"")
                      .append(esc(isDefault ? entryCheck(backendBase, entryRva) : ""))
                      .append("\",\"return_type\":\"")
                      .append(esc(String.valueOf(f.getReturnType())))
                      .append("\",\"code\":\"").append(esc(code)).append("\"}");
                } else {
                    printerr("decompiling " + f.getName() + " failed: "
                            + (res == null ? "no result" : res.getErrorMessage()));
                }
            }
        } finally {
            decomp.dispose();
            sb.append("]");
            OutputStreamWriter w = new OutputStreamWriter(
                    new FileOutputStream(outPath), StandardCharsets.UTF_8);
            try {
                w.write(sb.toString());
            } finally {
                w.close();
            }
            println("SupwngoDecompile wrote " + outPath);
        }
    }
}
