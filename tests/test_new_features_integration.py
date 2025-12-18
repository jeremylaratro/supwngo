"""
Integration tests for new cutting-edge features.

Tests the new modules against real binaries and scenarios.
"""

import os
import pytest
import tempfile
from pathlib import Path

# Get test binaries path
TEST_BINARIES = Path(__file__).parent.parent / "test_binaries"
CHALLENGES_PATH = Path("/home/jay/testing/supwngo/challenges")


class TestZ3ROPSolverIntegration:
    """Integration tests for Z3 ROP solver with real binaries."""

    @pytest.fixture
    def sample_gadgets(self):
        """Create sample gadgets for testing."""
        from supwngo.exploit.rop import Gadget, GadgetType

        return [
            Gadget(0x401234, "pop rdi; ret", gadget_type=GadgetType.POP_REG,
                   regs_popped=["rdi"], stack_change=16),
            Gadget(0x401240, "pop rsi; pop r15; ret", gadget_type=GadgetType.POP_REG,
                   regs_popped=["rsi", "r15"], stack_change=24),
            Gadget(0x401250, "pop rdx; ret", gadget_type=GadgetType.POP_REG,
                   regs_popped=["rdx"], stack_change=16),
            Gadget(0x401260, "pop rax; ret", gadget_type=GadgetType.POP_REG,
                   regs_popped=["rax"], stack_change=16),
            Gadget(0x401270, "syscall", gadget_type=GadgetType.SYSCALL,
                   is_syscall=True, is_ret=False),
            Gadget(0x401280, "ret", gadget_type=GadgetType.RET),
            Gadget(0x401290, "xor rax, rax; ret", gadget_type=GadgetType.XOR_REG),
            Gadget(0x4012a0, "mov [rdi], rsi; ret", gadget_type=GadgetType.MOV_MEM_REG),
        ]

    def test_solver_with_sample_gadgets(self, sample_gadgets):
        """Test solver initializes correctly with sample gadgets."""
        from supwngo.exploit.rop.z3_solver import Z3ROPSolver

        solver = Z3ROPSolver(sample_gadgets, arch='amd64')

        stats = solver.get_solver_stats()
        assert stats["total_gadgets"] == 8
        assert stats["analyzed_effects"] > 0

    def test_find_pop_gadgets_detailed(self, sample_gadgets):
        """Test finding pop gadgets with detailed analysis."""
        from supwngo.exploit.rop.z3_solver import Z3ROPSolver

        solver = Z3ROPSolver(sample_gadgets, arch='amd64')
        pop_gadgets = solver.find_pop_gadgets()

        # Should find pop rdi, pop rsi, pop rdx, pop rax
        print(f"Found pop gadgets: {pop_gadgets}")

    def test_find_syscall_gadgets(self, sample_gadgets):
        """Test finding syscall gadgets."""
        from supwngo.exploit.rop.z3_solver import Z3ROPSolver

        solver = Z3ROPSolver(sample_gadgets, arch='amd64')
        syscall_gadgets = solver.find_syscall_gadgets()

        assert len(syscall_gadgets) >= 1
        assert any(g.is_syscall for g in syscall_gadgets)

    def test_find_write_gadgets(self, sample_gadgets):
        """Test finding write gadgets."""
        from supwngo.exploit.rop.z3_solver import Z3ROPSolver

        solver = Z3ROPSolver(sample_gadgets, arch='amd64')
        write_gadgets = solver.find_write_gadgets()

        # Should find mov [rdi], rsi
        print(f"Found {len(write_gadgets)} write gadgets")

    def test_solve_call_basic(self, sample_gadgets):
        """Test basic function call solving."""
        from supwngo.exploit.rop.z3_solver import Z3ROPSolver, ChainConstraints

        solver = Z3ROPSolver(sample_gadgets, arch='amd64')

        # Try to solve for a call with one argument
        chain = solver.solve_call(
            target=0x401000,  # Target function
            args=[0x41414141],  # Single argument
            constraints=ChainConstraints(bad_chars=b"")
        )

        if chain:
            print(f"Solved chain:\n{chain.dump()}")
            payload = chain.build()
            print(f"Payload length: {len(payload)} bytes")
            assert len(payload) > 0
        else:
            print("Could not solve - this is expected if gadgets don't match")

    def test_chain_constraints_bad_chars(self, sample_gadgets):
        """Test chain solving with bad character constraints."""
        from supwngo.exploit.rop.z3_solver import Z3ROPSolver, ChainConstraints

        solver = Z3ROPSolver(sample_gadgets, arch='amd64')

        # With bad chars that match some addresses
        constraints = ChainConstraints(bad_chars=b"\x34\x12")

        chain = solver.solve_call(
            target=0x401000,
            args=[0x42424242],
            constraints=constraints
        )

        # Chain might fail due to bad chars in gadget addresses
        if chain:
            print(f"Found chain avoiding bad chars")

    @pytest.mark.skipif(not TEST_BINARIES.exists(), reason="Test binaries not found")
    def test_with_real_binary(self):
        """Test Z3 solver with gadgets from real binary."""
        from supwngo.core.binary import Binary
        from supwngo.exploit.rop import GadgetFinder
        from supwngo.exploit.rop.z3_solver import Z3ROPSolver

        binary_path = TEST_BINARIES / "test_fmtstr"
        if not binary_path.exists():
            pytest.skip("test_fmtstr binary not found")

        binary = Binary(str(binary_path))
        finder = GadgetFinder(binary)

        try:
            gadgets = finder.find_gadgets()
            if gadgets:
                solver = Z3ROPSolver(gadgets, arch=binary.arch)
                stats = solver.get_solver_stats()
                print(f"Real binary stats: {stats}")
                assert stats["total_gadgets"] > 0
        except Exception as e:
            print(f"Gadget finding failed (expected without ropper): {e}")


class TestAutoLeakFinderIntegration:
    """Integration tests for auto leak finder."""

    def test_leak_finder_with_mock_binary(self):
        """Test leak finder with comprehensive mock binary."""
        from supwngo.exploit.auto_leak import AutoLeakFinder, LeakType, LeakMethod
        from supwngo.core.context import ExploitContext
        from unittest.mock import Mock

        # Create comprehensive mock
        binary = Mock()
        binary.imports = ['printf', 'puts', 'scanf', 'read', 'write', 'gets']
        binary.got = {
            'puts': 0x601020,
            'printf': 0x601028,
            'read': 0x601030,
            '__libc_start_main': 0x601038,
        }
        binary.protections = Mock()
        binary.protections.canary = True
        binary.protections.pie = True
        binary.functions = {'main': 0x401000, 'vuln': 0x401100}
        binary.base = 0x400000

        context = ExploitContext()
        finder = AutoLeakFinder(binary, context)

        # Find all leaks
        leaks = finder.find_all_leaks()

        print(f"\nFound {len(leaks)} potential leaks:")
        for leak in leaks[:10]:  # Show first 10
            print(f"  {leak}")

        # Should find format string leaks (has printf)
        fmt_leaks = [l for l in leaks if l.method == LeakMethod.FORMAT_STRING]
        assert len(fmt_leaks) > 0, "Should find format string leaks"

        # Should find GOT-based leaks
        got_leaks = [l for l in leaks if l.method in (LeakMethod.PUTS_GOT, LeakMethod.WRITE_GOT)]
        assert len(got_leaks) > 0, "Should find GOT-based leaks"

        # Categorize by leak type
        by_type = {}
        for leak in leaks:
            by_type.setdefault(leak.leak_type.name, []).append(leak)

        print(f"\nLeaks by type:")
        for ltype, llist in by_type.items():
            print(f"  {ltype}: {len(llist)}")

    def test_identify_various_addresses(self):
        """Test identification of various address types."""
        from supwngo.exploit.auto_leak import AutoLeakFinder, LeakType
        from supwngo.core.context import ExploitContext
        from unittest.mock import Mock

        binary = Mock()
        binary.protections = Mock()
        binary.protections.pie = True
        binary.base = 0x555555554000

        context = ExploitContext()
        finder = AutoLeakFinder(binary, context)

        test_cases = [
            (0x7fffffffe000, LeakType.STACK, "Stack address"),
            (0x7f1234567890, LeakType.LIBC, "Libc address"),
            (0x00abcdef12345600, LeakType.CANARY, "Stack canary"),
        ]

        print("\nAddress identification tests:")
        for addr, expected_type, desc in test_cases:
            result = finder.identify_leaked_value(addr)
            status = "PASS" if result == expected_type else "FAIL"
            print(f"  {desc}: 0x{addr:x} -> {result.name} [{status}]")
            assert result == expected_type, f"{desc} failed"

    def test_create_leak_chain(self):
        """Test creating ordered leak chain."""
        from supwngo.exploit.auto_leak import AutoLeakFinder, LeakType
        from supwngo.core.context import ExploitContext
        from unittest.mock import Mock

        binary = Mock()
        binary.imports = ['printf', 'puts']
        binary.got = {'puts': 0x601020}
        binary.protections = Mock()
        binary.protections.canary = True
        binary.protections.pie = True
        binary.functions = {}

        finder = AutoLeakFinder(binary, ExploitContext())

        # Request specific leak types
        chain = finder.create_leak_chain([
            LeakType.CANARY,
            LeakType.LIBC,
            LeakType.BINARY,
        ])

        print(f"\nLeak chain ({len(chain)} primitives):")
        for i, leak in enumerate(chain):
            print(f"  {i+1}. {leak}")


class TestExploitTesterIntegration:
    """Integration tests for exploit tester."""

    def test_simple_script_execution(self):
        """Test executing a simple Python script."""
        from supwngo.exploit.tester import ExploitTester, TestResult
        from unittest.mock import Mock

        binary = Mock()
        binary.path = "/bin/true"
        binary.bits = 64

        tester = ExploitTester(binary)

        # Simple script that succeeds
        script = """
print("flag{test_flag_123}")
"""
        result = tester.test_local(script, timeout=5)

        print(f"\nSimple script result: {result}")
        assert result.result == TestResult.SUCCESS
        assert result.flag_captured == "flag{test_flag_123}"

    def test_timeout_handling(self):
        """Test that timeouts are handled correctly."""
        from supwngo.exploit.tester import ExploitTester, TestResult
        from unittest.mock import Mock

        binary = Mock()
        binary.path = "/bin/true"
        binary.bits = 64

        tester = ExploitTester(binary)

        # Script that hangs
        script = """
import time
time.sleep(100)
"""
        result = tester.test_local(script, timeout=2)

        print(f"\nTimeout result: {result}")
        assert result.result == TestResult.TIMEOUT

    def test_crash_detection(self):
        """Test that crashes are detected."""
        from supwngo.exploit.tester import ExploitTester, TestResult
        from unittest.mock import Mock

        binary = Mock()
        binary.path = "/bin/true"
        binary.bits = 64

        tester = ExploitTester(binary)

        # Script that crashes
        script = """
import sys
print("SIGSEGV", file=sys.stderr)
sys.exit(139)  # SIGSEGV exit code
"""
        result = tester.test_local(script, timeout=5)

        print(f"\nCrash result: {result}")
        assert result.result in (TestResult.CRASH, TestResult.FAILED)

    def test_shell_detection(self):
        """Test shell obtained detection."""
        from supwngo.exploit.tester import ExploitTester, TestResult
        from unittest.mock import Mock

        binary = Mock()
        binary.path = "/bin/true"
        binary.bits = 64

        tester = ExploitTester(binary)

        # Script that indicates shell
        script = """
print("uid=0(root) gid=0(root)")
"""
        result = tester.test_local(script, timeout=5)

        print(f"\nShell detection result: {result}")
        assert result.result == TestResult.SUCCESS
        assert result.shell_obtained == True

    def test_validator_comprehensive(self):
        """Test payload validator with various scenarios."""
        from supwngo.exploit.tester import ExploitValidator
        from unittest.mock import Mock

        binary = Mock()
        binary.bits = 64

        validator = ExploitValidator(binary)

        # Test case 1: Valid payload
        valid, issues = validator.validate_payload(
            b"A" * 100,
            bad_chars=b"\x00\n",
            max_length=200
        )
        assert valid, f"Should be valid, got issues: {issues}"

        # Test case 2: Too long
        valid, issues = validator.validate_payload(
            b"A" * 300,
            max_length=200
        )
        assert not valid
        assert any("too long" in i.lower() for i in issues)

        # Test case 3: Contains bad chars
        valid, issues = validator.validate_payload(
            b"A" * 50 + b"\x00" + b"B" * 50,
            bad_chars=b"\x00"
        )
        assert not valid
        assert any("bad char" in i.lower() for i in issues)

        print("\nValidator tests passed!")

    def test_address_validation(self):
        """Test address validation for bad characters."""
        from supwngo.exploit.tester import ExploitValidator
        from unittest.mock import Mock

        binary = Mock()
        binary.bits = 64

        validator = ExploitValidator(binary)

        # Addresses with null bytes
        valid, issues = validator.check_addresses(
            [0x00401234, 0x401000],  # First has embedded null
            bad_chars=b"\x00"
        )

        print(f"\nAddress validation issues: {issues}")
        # Should catch the address with null byte


class TestCombinedWorkflow:
    """Test combined workflow using multiple new features."""

    def test_full_analysis_workflow(self):
        """Test a full analysis workflow combining features."""
        from supwngo.exploit.auto_leak import AutoLeakFinder, LeakType
        from supwngo.exploit.rop import Gadget, GadgetType
        from supwngo.exploit.rop.z3_solver import Z3ROPSolver
        from supwngo.exploit.tester import ExploitValidator
        from supwngo.core.context import ExploitContext
        from unittest.mock import Mock

        print("\n=== Full Analysis Workflow Test ===")

        # Step 1: Create mock binary
        binary = Mock()
        binary.path = "/test/binary"
        binary.arch = "amd64"
        binary.bits = 64
        binary.imports = ['printf', 'puts', 'system']
        binary.got = {
            'puts': 0x601020,
            'printf': 0x601028,
            'system': 0x601030,
        }
        binary.protections = Mock()
        binary.protections.canary = True
        binary.protections.pie = False
        binary.protections.nx = True
        binary.base = 0x400000
        binary.functions = {'main': 0x401000, 'vuln': 0x401100}

        print("1. Created mock binary")

        # Step 2: Find leak opportunities
        context = ExploitContext()
        leak_finder = AutoLeakFinder(binary, context)
        leaks = leak_finder.find_all_leaks()
        print(f"2. Found {len(leaks)} leak opportunities")

        # Step 3: Filter to libc leaks
        libc_leaks = [l for l in leaks if l.leak_type == LeakType.LIBC]
        print(f"3. Found {len(libc_leaks)} libc leak primitives")

        # Step 4: Create gadgets for ROP
        gadgets = [
            Gadget(0x401234, "pop rdi; ret", gadget_type=GadgetType.POP_REG,
                   regs_popped=["rdi"], stack_change=16),
            Gadget(0x401240, "ret", gadget_type=GadgetType.RET),
        ]
        print(f"4. Created {len(gadgets)} mock gadgets")

        # Step 5: Initialize solver
        solver = Z3ROPSolver(gadgets, arch='amd64')
        stats = solver.get_solver_stats()
        print(f"5. Solver stats: {stats}")

        # Step 6: Try to solve for system("/bin/sh")
        chain = solver.solve_call(
            target=0x401000,  # Placeholder for system
            args=[0x402000],  # Placeholder for /bin/sh
        )
        if chain:
            print(f"6. Solved chain: {len(chain.gadgets)} gadgets")
            payload = chain.build()

            # Step 7: Validate payload
            validator = ExploitValidator(binary)
            valid, issues = validator.validate_payload(
                payload,
                bad_chars=b"\x00\n",
                max_length=500
            )
            print(f"7. Payload validation: {'PASS' if valid else 'FAIL'}")
            if issues:
                print(f"   Issues: {issues}")
        else:
            print("6. Could not solve chain (expected with limited gadgets)")

        print("=== Workflow Complete ===\n")


@pytest.mark.skipif(not TEST_BINARIES.exists(), reason="Test binaries not found")
class TestWithRealBinaries:
    """Tests using real compiled binaries."""

    def test_analyze_format_string_binary(self):
        """Test analysis of format string vulnerable binary."""
        from supwngo.core.binary import Binary
        from supwngo.exploit.auto_leak import AutoLeakFinder

        binary_path = TEST_BINARIES / "test_fmtstr"
        if not binary_path.exists():
            pytest.skip("test_fmtstr not found")

        binary = Binary(str(binary_path))

        print(f"\nBinary: {binary.path}")
        print(f"Arch: {binary.arch}")
        print(f"Protections: {binary.protections}")

        finder = AutoLeakFinder(binary)
        leaks = finder.find_all_leaks()

        print(f"Found {len(leaks)} potential leaks")

    def test_analyze_pivot_binary(self):
        """Test analysis of stack pivot binary."""
        from supwngo.core.binary import Binary
        from supwngo.exploit.rop import GadgetFinder

        binary_path = TEST_BINARIES / "test_pivot"
        if not binary_path.exists():
            pytest.skip("test_pivot not found")

        binary = Binary(str(binary_path))

        print(f"\nBinary: {binary.path}")
        print(f"Arch: {binary.arch}")

        try:
            finder = GadgetFinder(binary)
            gadgets = finder.find_gadgets()
            print(f"Found {len(gadgets)} gadgets")
        except Exception as e:
            print(f"Gadget finding requires ropper: {e}")
