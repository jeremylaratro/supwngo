// SupwngoPayoffSelfTest.java - companion self-test for the W-2 parity seam
// (design doc docs/plans/2026-11-13-w2-required-args-design.md, Rev 11, T14b).
//
// Run via analyzeHeadless -postScript, using the same temp-project pattern
// payoff.py's driver uses for SupwngoPayoff itself (see payoff.py's
// GHIDRA_PAYOFF_SCRIPT runner). This script does NOT decompile anything: it
// exercises SupwngoPayoff's Ghidra-state-free static parity seam --
// resolveConditionFromPeeled / step1EmitsEquality / step2SelectedEdgeIsTrue,
// themselves built on flipParity / accumulateNegateParity / edgeMeansEqual --
// directly, as a live JVM/class-loader check that T14a's pure-Python mirror
// (tests/test_payoff_ranker.py) cannot give: it proves this companion script
// can actually see and call SupwngoPayoff's package-private statics and
// its package-private ResolvedComparison type from a real analyzeHeadless
// run, not just that the underlying algebra is sound.
//
// Exercises the peel sequences from design §2.2's worked examples --
// {[], [BOOL_NEGATE], [BOOL_NEGATE,BOOL_NEGATE], [COPY,BOOL_NEGATE,CAST]} --
// crossed with cmpOpcode in {INT_EQUAL, INT_NOTEQUAL}, 8 cases total. Each
// case checks the stored parity (expected 0/1/0/1 by peel sequence, the same
// for both cmpOpcodes since accumulateNegateParity never looks at cmpOpcode)
// and then feeds the SAME ResolvedComparison into both step1EmitsEquality and
// step2SelectedEdgeIsTrue over both edges, checking the involution identity
// step2SelectedEdgeIsTrue(rc, step1EmitsEquality(rc, edge)) == edge that holds
// for any rc (edgeMeansEqual is its own inverse in the second argument) --
// this is the concrete form of "the same rc goes into both consumers over
// both edges".
//
// Writes one "PASS"/"FAIL:<case>" line per case, then a trailing
// "ALL_PASS <n>" line, to the path given as arg0. decompile.py's headless
// runner treats any ended process as finished regardless of exit code, so
// the caller reads this artifact rather than trusting the process's exit
// status.
//@category Supwngo

import ghidra.app.script.GhidraScript;
import ghidra.program.model.pcode.PcodeOp;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class SupwngoPayoffSelfTest extends GhidraScript {

    private static final int[][] PEEL_SEQS = {
        {},
        {PcodeOp.BOOL_NEGATE},
        {PcodeOp.BOOL_NEGATE, PcodeOp.BOOL_NEGATE},
        {PcodeOp.COPY, PcodeOp.BOOL_NEGATE, PcodeOp.CAST},
    };
    private static final String[] PEEL_NAMES = {"peel0", "peel1", "peel2", "peel3"};
    private static final int[] EXPECTED_PARITY = {0, 1, 0, 1};
    private static final int[] CMP_OPS = {PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL};
    private static final String[] CMP_NAMES = {"EQUAL", "NOTEQUAL"};

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args[0];

        List<String> lines = new ArrayList<>();
        int passCount = 0;

        for (int p = 0; p < PEEL_SEQS.length; p++) {
            for (int c = 0; c < CMP_OPS.length; c++) {
                String caseName = PEEL_NAMES[p] + ":" + CMP_NAMES[c];
                boolean ok;
                try {
                    ok = runCase(PEEL_SEQS[p], EXPECTED_PARITY[p], CMP_OPS[c]);
                } catch (Exception e) {
                    ok = false;
                }
                lines.add(ok ? "PASS" : ("FAIL:" + caseName));
                if (ok) {
                    passCount++;
                }
            }
        }
        lines.add("ALL_PASS " + passCount);

        OutputStreamWriter w = new OutputStreamWriter(
                new FileOutputStream(outPath), StandardCharsets.UTF_8);
        try {
            for (String line : lines) {
                w.write(line);
                w.write('\n');
            }
        } finally {
            w.close();
        }
        println("SupwngoPayoffSelfTest wrote " + outPath + " (" + passCount + "/"
                + lines.size() + " pass lines)");
    }

    /**
     * One case: build rc via SupwngoPayoff.resolveConditionFromPeeled, check its
     * stored parity/opcode, then round-trip the SAME rc through both consumers
     * over both edges.
     */
    private static boolean runCase(int[] peeled, int expectedParity, int cmpOpcode) {
        SupwngoPayoff.ResolvedComparison rc =
                SupwngoPayoff.resolveConditionFromPeeled(cmpOpcode, peeled);
        if (rc.negateParity != expectedParity || rc.cmpOpcode != cmpOpcode) {
            return false;
        }
        boolean[] edges = {true, false};
        for (boolean edge : edges) {
            boolean eq = SupwngoPayoff.step1EmitsEquality(rc, edge);
            boolean roundTrip = SupwngoPayoff.step2SelectedEdgeIsTrue(rc, eq);
            if (roundTrip != edge) {
                return false;
            }
        }
        return true;
    }
}
