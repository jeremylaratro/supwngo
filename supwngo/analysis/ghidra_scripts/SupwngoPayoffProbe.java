// SupwngoPayoffProbe.java - structural P-code probe for the W-2 falsifier tests
// (design doc docs/plans/2026-11-13-w2-required-args-design.md, Rev 11, section 6
// T4: the "structural P-code probe" assertions).
//
// A TEST AID, not a product script: it never feeds payoff ranking. It decompiles
// ONE function and writes a small JSON object describing the high P-code the
// extractor (SupwngoPayoff.java) actually saw, so tests/test_payoff_ranker.py
// can assert the shape each falsifier is *supposed* to have rather than trusting
// the generator's C source:
//   - gate_bool      : the composed condition is an INT_AND/BOOL_AND op
//   - gate_boolor    : a short-circuit `||` is >= 2 CBRANCHes with no BOOL_OR
//   - gate_loop      : a real back-edge cycle with no exit (SCC with no out-edge)
//   - gate_reload /
//     gate_nonconst* : a compare operand that is memory-resident
//   - gate_negeq/neginv : whether a BOOL_NEGATE survived into the high P-code
//   - gate_abistack  : the 7th formal's storage is stack (no register)
//
// Like SupwngoPayoffSelfTest it lives in the shared ghidra_scripts directory and
// is driven by analyzeHeadless -postScript with the temp-project pattern
// payoff.py's driver uses.
//
// Script args (positional):
//   arg0  output JSON path
//   arg1  function entry address (hex, absolute, e.g. 0x4011b6)
//@category Supwngo

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class SupwngoPayoffProbe extends GhidraScript {

    private static final int TRACE_DEPTH = 16;

    /**
     * Independent (does not share code with SupwngoPayoff) coarse classifier of a
     * compare operand: const / param / mem / input / op:MNEMONIC. Ghidra 12.1.3
     * represents a global read as a bare RAM-space input varnode with a
     * HighVariable (no LOAD op), so "mem" covers both that and a real LOAD.
     */
    private static String kind(Varnode v) {
        for (int guard = 0; guard < TRACE_DEPTH; guard++) {
            if (v == null) {
                return "null";
            }
            if (v.isConstant()) {
                return "const";
            }
            PcodeOp d = v.getDef();
            if (d == null) {
                HighVariable hv = v.getHigh();
                if (v.isInput() && hv instanceof HighParam) {
                    return "param";
                }
                if (v.getAddress().isMemoryAddress() && hv != null) {
                    return "mem";
                }
                return "input";
            }
            int opc = d.getOpcode();
            if (opc == PcodeOp.COPY || opc == PcodeOp.CAST
                    || opc == PcodeOp.INT_ZEXT || opc == PcodeOp.INT_SEXT) {
                v = d.getInput(0);
                continue;
            }
            if (opc == PcodeOp.LOAD) {
                return "mem";
            }
            return "op:" + d.getMnemonic();
        }
        return "deep";
    }

    /** Tarjan SCC state over the basic-block graph. */
    private static final class Scc {
        final List<PcodeBlockBasic> blocks;
        final Map<PcodeBlockBasic, Integer> index = new HashMap<>();
        final Map<PcodeBlockBasic, Integer> low = new HashMap<>();
        final List<PcodeBlockBasic> stack = new ArrayList<>();
        final Map<PcodeBlockBasic, Boolean> onStack = new HashMap<>();
        final List<List<PcodeBlockBasic>> components = new ArrayList<>();
        int counter = 0;

        Scc(List<PcodeBlockBasic> blocks) {
            this.blocks = blocks;
        }

        void run() {
            for (PcodeBlockBasic b : blocks) {
                if (!index.containsKey(b)) {
                    strong(b);
                }
            }
        }

        private void strong(PcodeBlockBasic v) {
            index.put(v, counter);
            low.put(v, counter);
            counter++;
            stack.add(v);
            onStack.put(v, Boolean.TRUE);
            for (int i = 0; i < v.getOutSize(); i++) {
                PcodeBlockBasic w = (PcodeBlockBasic) v.getOut(i);
                if (!index.containsKey(w)) {
                    strong(w);
                    low.put(v, Math.min(low.get(v), low.get(w)));
                } else if (Boolean.TRUE.equals(onStack.get(w))) {
                    low.put(v, Math.min(low.get(v), index.get(w)));
                }
            }
            if (low.get(v).equals(index.get(v))) {
                List<PcodeBlockBasic> comp = new ArrayList<>();
                PcodeBlockBasic w;
                do {
                    w = stack.remove(stack.size() - 1);
                    onStack.put(w, Boolean.FALSE);
                    comp.add(w);
                } while (w != v);
                components.add(comp);
            }
        }
    }

    /**
     * True iff some SCC contains a real cycle (size > 1, or a self-loop) and has
     * NO way out: no edge to a block outside the SCC and no member that is itself
     * a terminal block (outSize == 0, i.e. a return/exit).
     */
    private static boolean hasExitlessCycle(List<PcodeBlockBasic> blocks) {
        Scc scc = new Scc(blocks);
        scc.run();
        for (List<PcodeBlockBasic> comp : scc.components) {
            boolean cyclic = comp.size() > 1;
            boolean exits = false;
            for (PcodeBlockBasic b : comp) {
                if (b.getOutSize() == 0) {
                    exits = true;
                }
                for (int i = 0; i < b.getOutSize(); i++) {
                    PcodeBlock t = b.getOut(i);
                    if (t == b) {
                        cyclic = true;
                    }
                    if (!comp.contains(t)) {
                        exits = true;
                    }
                }
            }
            if (cyclic && !exits) {
                return true;
            }
        }
        return false;
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') {
                sb.append('\\').append(c);
            } else if (c < 0x20) {
                sb.append(String.format("\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args[0];
        String addrText = args[1];
        long off = Long.decode(addrText);
        Address entry = currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(off);
        Function f = currentProgram.getFunctionManager().getFunctionAt(entry);

        StringBuilder sb = new StringBuilder();
        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(currentProgram);
            HighFunction hf = null;
            if (f != null) {
                DecompileResults res = decomp.decompileFunction(
                        f, 120, new ConsoleTaskMonitor());
                hf = res == null ? null : res.getHighFunction();
            }
            if (f == null || hf == null) {
                sb.append("{\"function\":\"").append(f == null ? "" : esc(f.getName()))
                  .append("\",\"decompiled\":false}");
            } else {
                Map<String, Integer> ops = new TreeMap<>();
                List<String> compares = new ArrayList<>();
                Iterator<PcodeOpAST> it = hf.getPcodeOps();
                while (it.hasNext()) {
                    PcodeOpAST op = it.next();
                    String m = op.getMnemonic();
                    Integer n = ops.get(m);
                    ops.put(m, n == null ? 1 : n + 1);
                    int opc = op.getOpcode();
                    if (opc == PcodeOp.INT_EQUAL || opc == PcodeOp.INT_NOTEQUAL) {
                        compares.add("{\"op\":\"" + m + "\",\"kinds\":[\""
                                + esc(kind(op.getInput(0))) + "\",\""
                                + esc(kind(op.getInput(1))) + "\"]}");
                    }
                }
                List<PcodeBlockBasic> blocks = hf.getBasicBlocks();

                sb.append("{\"function\":\"").append(esc(f.getName()))
                  .append("\",\"decompiled\":true")
                  .append(",\"block_count\":").append(blocks.size())
                  .append(",\"has_exitless_cycle\":").append(hasExitlessCycle(blocks))
                  .append(",\"ops\":{");
                boolean first = true;
                for (Map.Entry<String, Integer> e : ops.entrySet()) {
                    if (!first) {
                        sb.append(',');
                    }
                    first = false;
                    sb.append('"').append(esc(e.getKey())).append("\":").append(e.getValue());
                }
                sb.append("},\"compares\":[");
                for (int i = 0; i < compares.size(); i++) {
                    if (i > 0) {
                        sb.append(',');
                    }
                    sb.append(compares.get(i));
                }
                sb.append("],\"params\":[");
                LocalSymbolMap lsm = hf.getLocalSymbolMap();
                for (int i = 0; i < lsm.getNumParams(); i++) {
                    HighParam hp = lsm.getParam(i);
                    VariableStorage st = hp.getSymbol().getStorage();
                    Register r = st.isRegisterStorage() ? st.getRegister() : null;
                    if (i > 0) {
                        sb.append(',');
                    }
                    sb.append("{\"slot\":").append(hp.getSlot())
                      .append(",\"size\":").append(hp.getSize())
                      .append(",\"register\":");
                    if (r == null) {
                        sb.append("null");
                    } else {
                        sb.append('"').append(esc(r.getName())).append('"');
                    }
                    sb.append(",\"stack\":").append(st.isStackStorage()).append('}');
                }
                sb.append("]}");
            }
        } finally {
            decomp.dispose();
            OutputStreamWriter w = new OutputStreamWriter(
                    new FileOutputStream(outPath), StandardCharsets.UTF_8);
            try {
                w.write(sb.toString());
            } finally {
                w.close();
            }
        }
        println("SupwngoPayoffProbe wrote " + outPath);
    }
}
