// SupwngoDecompile.java - headless Ghidra decompilation for supwngo.
//
// Driven by supwngo.analysis.decompile.Decompiler._decompile_ghidra via
// analyzeHeadless. This file MUST live in its own near-empty directory: Ghidra
// enumerates every file in each -scriptPath directory to classify scripts, so a
// crowded directory (e.g. /tmp) hangs postScript resolution. A .java script is
// used deliberately -- Ghidra 12.x without PyGhidra cannot run .py scripts.
//
// Script args: arg0 = tagged target selector, arg1 = output JSON path,
// arg2 = the file's link-time base (hex), or "none" when the caller has none.
//   "name:<fname>"  -> first global function with that name
//   "addr:<0xNN|NN>" -> function whose entry point is that address
//   ""/"all"         -> "main", else the first defined function
// A tagged selector is used so a function literally named "0x..." or "123" is
// still selectable by name, and so name-vs-address precedence is explicit.
//
// Address convention: an "addr:" selector is in the *file's* convention (the
// one objdump/nm print). Ghidra loads a program at its own image base, so the
// selector is mapped with  ghidra = image_base + (selector - arg2)  before the
// lookup. The output reports Ghidra's own address and its image base
// ("backend_base"); the caller maps the address back with the same two bases.
// Always writes a UTF-8 JSON array (possibly empty "[]") to arg1 so the caller
// can distinguish "ran but found nothing" from "never ran".
//@category Supwngo

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;

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

    /**
     * Resolve the function to decompile from the tagged arg0 selector. fileBase
     * is the file's link-time base (null if unknown); backendBase is Ghidra's
     * image base for the loaded program.
     */
    private Function resolveFunction(String selector, Long fileBase,
                                     long backendBase) {
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
                return fm.getFunctionAt(addr);
            } catch (Exception e) {
                return null;
            }
        }

        if (selector != null && selector.startsWith("name:")) {
            String name = selector.substring("name:".length());
            List<Function> named = getGlobalFunctions(name);
            if (named != null && !named.isEmpty()) {
                return named.get(0);
            }
            return null;
        }

        // Empty / "all": prefer main, else the first defined function.
        List<Function> mains = getGlobalFunctions("main");
        if (mains != null && !mains.isEmpty()) {
            return mains.get(0);
        }
        java.util.Iterator<Function> it = fm.getFunctions(true);
        if (it.hasNext()) {
            return it.next();
        }
        return null;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String selector = (args.length > 0 && args[0] != null) ? args[0] : "";
        String outPath = (args.length > 1 && args[1] != null && !args[1].isEmpty())
                ? args[1] : "supwngo_decompile.json";
        Long fileBase = args.length > 2 ? parseOffset(args[2]) : null;
        long backendBase = currentProgram.getImageBase().getOffset();

        StringBuilder sb = new StringBuilder("[");

        try {
            Function f = resolveFunction(selector, fileBase, backendBase);
            if (f != null) {
                DecompInterface decomp = new DecompInterface();
                try {
                    decomp.openProgram(currentProgram);
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
                          .append(",\"return_type\":\"")
                          .append(esc(String.valueOf(f.getReturnType())))
                          .append("\",\"code\":\"").append(esc(code)).append("\"}");
                    }
                } finally {
                    decomp.dispose();
                }
            }
        } finally {
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
