#!/usr/bin/env python3
"""
Test suite for ROP exploitation modules.

Tests the following modules:
- ret2csu
- ret2dlresolve
- ROP optimizer
- Stack pivot
"""

import os
import sys
import unittest
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from supwngo.exploit.rop import (
    # ret2csu
    Ret2CSU,
    CSUGadgetInfo,
    ret2csu_chain,
    # ret2dlresolve
    Ret2dlresolve,
    Ret2dlresolvePayload,
    # Optimizer
    ROPOptimizer,
    ChainMinimizer,
    GadgetCandidate,
    Operation,
    optimize_rop_chain,
    # Pivot
    StackPivot,
    PivotType,
    PivotGadget,
    PivotPayload,
    # Basic
    GadgetFinder,
    Gadget,
    GadgetType,
    ROPChainBuilder,
    ROPTechniques,
)


class MockBinary:
    """Mock binary for testing."""

    def __init__(self, bits=64, has_csu=True):
        self.bits = bits
        self._bits = bits
        self.path = type('obj', (object,), {'name': 'test_binary'})()

        # Mock symbols
        if has_csu:
            self.symbols = {
                '__libc_csu_init': MockSymbol(0x401200),
                'main': MockSymbol(0x401100),
                'puts': MockSymbol(0x401030),
            }
        else:
            self.symbols = {
                'main': MockSymbol(0x401100),
            }

        # Mock sections
        self.plt = {'puts': 0x401030, 'read': 0x401040}
        self.got = {'puts': 0x404018, 'read': 0x404020}

        # Mock memory for reading
        self._memory = {
            # Fake __libc_csu_init with gadgets
            0x401200: self._make_csu_init(),
        }

    def _make_csu_init(self):
        """Create fake __libc_csu_init bytes."""
        if self.bits == 64:
            # Include both gadget patterns
            data = bytearray(0x80)

            # Gadget 2 at offset 0x30: mov rdx, r15; mov rsi, r14; mov edi, r13d
            g2 = bytes([0x4c, 0x89, 0xfa, 0x4c, 0x89, 0xf6, 0x44, 0x89, 0xef, 0x41, 0xff, 0x14, 0xdc])
            data[0x30:0x30 + len(g2)] = g2

            # Gadget 1 at offset 0x50: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
            g1 = bytes([0x5b, 0x5d, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0xc3])
            data[0x50:0x50 + len(g1)] = g1

            return bytes(data)
        else:
            return b"\x00" * 0x80

    def read(self, addr, size):
        """Mock read function."""
        if addr in self._memory:
            data = self._memory[addr]
            return data[:size] if len(data) >= size else data + b"\x00" * (size - len(data))
        return b"\x00" * size


class MockSymbol:
    """Mock symbol for testing."""

    def __init__(self, address):
        self.address = address

    def __int__(self):
        return self.address

    def __gt__(self, other):
        return self.address > other

    def __lt__(self, other):
        return self.address < other

    def __eq__(self, other):
        if isinstance(other, MockSymbol):
            return self.address == other.address
        return self.address == other


class TestCSUGadgetInfo(unittest.TestCase):
    """Test CSUGadgetInfo dataclass."""

    def test_default_values(self):
        """Test default initialization."""
        info = CSUGadgetInfo()

        self.assertEqual(info.pop_gadget, 0)
        self.assertEqual(info.call_gadget, 0)
        self.assertEqual(info.csu_init_addr, 0)
        self.assertEqual(info.variant, "standard")

    def test_custom_values(self):
        """Test custom initialization."""
        info = CSUGadgetInfo(
            pop_gadget=0x401250,
            call_gadget=0x401230,
            csu_init_addr=0x401200,
            variant="gcc10",
        )

        self.assertEqual(info.pop_gadget, 0x401250)
        self.assertEqual(info.call_gadget, 0x401230)
        self.assertEqual(info.variant, "gcc10")


class TestRet2CSU(unittest.TestCase):
    """Test ret2csu module."""

    def setUp(self):
        self.binary = MockBinary(bits=64, has_csu=True)
        self.csu = Ret2CSU(self.binary)

    def test_initialization(self):
        """Test module initialization."""
        self.assertEqual(self.csu.bits, 64)
        self.assertIsNotNone(self.csu.gadgets)

    def test_gadget_finding(self):
        """Test gadget finding in __libc_csu_init."""
        gadgets = self.csu.gadgets

        # Should find gadgets at expected offsets
        self.assertGreater(gadgets.csu_init_addr, 0)

    def test_availability_check_with_csu(self):
        """Test availability when CSU exists."""
        available, reason = self.csu.is_available()

        # Check that we get a meaningful response
        self.assertIsInstance(available, bool)
        self.assertIsInstance(reason, str)
        self.assertGreater(len(reason), 0)

    def test_availability_check_without_csu(self):
        """Test availability when CSU doesn't exist."""
        binary_no_csu = MockBinary(bits=64, has_csu=False)
        csu = Ret2CSU(binary_no_csu)

        available, reason = csu.is_available()
        self.assertFalse(available)

    def test_chain_building(self):
        """Test chain building."""
        # Even if gadgets not found, should return something
        chain = self.csu.build_call(
            call_target=0x404018,
            arg1=0x1234,
            arg2=0x5678,
            arg3=0x9abc,
        )

        # If gadgets found, chain should be non-empty
        # If not found, should return empty bytes
        self.assertIsInstance(chain, bytes)

    def test_multiple_calls(self):
        """Test multiple call chain building."""
        calls = [
            {'target': 0x404018, 'arg1': 0x1234},
            {'target': 0x404020, 'arg1': 0x5678},
        ]

        chain = self.csu.build_multiple_calls(calls)
        self.assertIsInstance(chain, bytes)

    def test_exploit_template_generation(self):
        """Test exploit template generation."""
        template = self.csu.generate_exploit_template(
            func_got=0x404018,
            args=[0x1234, 0x5678, 0x9abc],
        )

        self.assertIn("ret2csu", template.lower())
        self.assertIn("from pwn import", template)
        self.assertIn("0x1234", template)


class TestRet2dlresolve(unittest.TestCase):
    """Test ret2dlresolve module."""

    def setUp(self):
        self.binary = MockBinary(bits=64)
        # Need to mock more ELF attributes for ret2dlresolve
        self.binary.dynamic_value_by_tag = lambda x: {
            'DT_JMPREL': 0x400400,
            'DT_SYMTAB': 0x400200,
            'DT_STRTAB': 0x400300,
            'DT_PLTGOT': 0x404000,
            'DT_RELAENT': 24,
            'DT_SYMENT': 24,
        }.get(x, 0)
        self.binary.bss = 0x404100

    def test_initialization(self):
        """Test module initialization."""
        resolver = Ret2dlresolve(self.binary, bits=64)

        self.assertEqual(resolver.bits, 64)
        self.assertEqual(resolver.ptr_size, 8)

    def test_payload_sizes(self):
        """Test payload structure sizes."""
        resolver = Ret2dlresolve(self.binary, bits=64)

        self.assertEqual(resolver.rel_size, 24)  # Elf64_Rela
        self.assertEqual(resolver.sym_size, 24)  # Elf64_Sym

        resolver_32 = Ret2dlresolve(self.binary, bits=32)
        self.assertEqual(resolver_32.rel_size, 8)   # Elf32_Rel
        self.assertEqual(resolver_32.sym_size, 16)  # Elf32_Sym

    def test_writable_area_finding(self):
        """Test writable area detection."""
        resolver = Ret2dlresolve(self.binary, bits=64)

        writable = resolver._find_writable_area()
        self.assertGreater(writable, 0)

    def test_payload_building(self):
        """Test payload building."""
        resolver = Ret2dlresolve(self.binary, bits=64)

        payload = resolver.build_payload(
            func_name="system",
            data_addr=0x404200,
        )

        self.assertIsInstance(payload, Ret2dlresolvePayload)
        self.assertEqual(payload.data_addr, 0x404200)
        self.assertGreater(len(payload.payload), 0)

    def test_exploit_code_generation(self):
        """Test exploit code generation."""
        resolver = Ret2dlresolve(self.binary, bits=64)

        code = resolver.generate_exploit_code(
            func_name="system",
            args=[0x404300],
        )

        self.assertIn("Ret2dlresolvePayload", code)
        self.assertIn("system", code)


class TestROPOptimizer(unittest.TestCase):
    """Test ROP optimizer module."""

    def setUp(self):
        self.binary = MockBinary(bits=64)
        self.opt = ROPOptimizer(self.binary, bits=64)

    def test_initialization(self):
        """Test optimizer initialization."""
        self.assertEqual(self.opt.bits, 64)
        self.assertEqual(self.opt.ptr_size, 8)

    def test_arg_registers(self):
        """Test argument register detection."""
        self.assertEqual(self.opt.arg_regs[0], 'rdi')
        self.assertEqual(self.opt.arg_regs[1], 'rsi')
        self.assertEqual(self.opt.arg_regs[2], 'rdx')

    def test_operation_enum(self):
        """Test operation enum values."""
        self.assertEqual(Operation.SET_REG.name, "SET_REG")
        self.assertEqual(Operation.SYSCALL.name, "SYSCALL")
        self.assertEqual(Operation.CALL_FUNC.name, "CALL_FUNC")

    def test_gadget_candidate(self):
        """Test GadgetCandidate dataclass."""
        candidate = GadgetCandidate(
            address=0x401234,
            bytes=b"\x5f\xc3",
            disasm="pop rdi; ret",
            quality=100,
        )

        self.assertEqual(candidate.address, 0x401234)
        self.assertEqual(candidate.quality, 100)
        self.assertEqual(candidate.disasm, "pop rdi; ret")

    def test_chain_size_estimation(self):
        """Test chain size estimation."""
        operations = ["set_rdi", "set_rsi", "syscall"]

        size = self.opt.estimate_chain_size(operations)

        # set_rdi: 16, set_rsi: 16, syscall: 8 = 40
        self.assertEqual(size, 40)

    def test_gadget_coverage_analysis(self):
        """Test gadget coverage analysis."""
        coverage = self.opt.analyze_gadget_coverage()

        # Should have entries for common registers
        self.assertIn("set_rax", coverage)
        self.assertIn("set_rdi", coverage)
        self.assertIn("syscall", coverage)


class TestChainMinimizer(unittest.TestCase):
    """Test chain minimizer."""

    def setUp(self):
        self.binary = MockBinary(bits=64)
        self.opt = ROPOptimizer(self.binary, bits=64)
        self.minimizer = ChainMinimizer(self.opt)

    def test_minimize_passthrough(self):
        """Test minimize returns chain unchanged if no optimization possible."""
        chain = b"A" * 64

        minimized = self.minimizer.minimize(chain)

        self.assertEqual(minimized, chain)

    def test_remove_nops(self):
        """Test NOP removal."""
        chain = b"A" * 64

        result = self.minimizer.remove_nops(chain)

        self.assertIsInstance(result, bytes)


class TestStackPivot(unittest.TestCase):
    """Test stack pivot module."""

    def test_pivot_type_enum(self):
        """Test PivotType enum."""
        self.assertEqual(PivotType.POP_RSP.name, "POP_RSP")
        self.assertEqual(PivotType.LEAVE_RET.name, "LEAVE_RET")
        self.assertEqual(PivotType.XCHG_RSP.name, "XCHG_RSP")

    def test_pivot_gadget_dataclass(self):
        """Test PivotGadget dataclass."""
        gadget = PivotGadget(
            address=0x401234,
            instructions="leave; ret",
            pivot_type=PivotType.LEAVE_RET,
        )

        self.assertEqual(gadget.address, 0x401234)
        self.assertEqual(gadget.pivot_type, PivotType.LEAVE_RET)

    def test_pivot_payload_dataclass(self):
        """Test PivotPayload dataclass."""
        payload = PivotPayload(
            payload=b"A" * 32,
            pivot_address=0x401234,
            target_buffer=0x7fffffffe000,
            pivot_type=PivotType.LEAVE_RET,
        )

        self.assertEqual(payload.target_buffer, 0x7fffffffe000)
        self.assertEqual(len(payload.payload), 32)


class TestGadgetTypes(unittest.TestCase):
    """Test basic gadget types."""

    def test_gadget_type_enum(self):
        """Test GadgetType enum values."""
        self.assertIn('POP_REG', GadgetType.__members__)
        self.assertIn('MOV_REG', GadgetType.__members__)
        self.assertIn('SYSCALL', GadgetType.__members__)

    def test_gadget_dataclass(self):
        """Test Gadget dataclass."""
        gadget = Gadget(
            address=0x401234,
            raw_bytes=b"\x5f\xc3",
            instructions="pop rdi; ret",
            gadget_type=GadgetType.POP_REG,
        )

        self.assertEqual(gadget.address, 0x401234)
        self.assertEqual(gadget.gadget_type, GadgetType.POP_REG)


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience functions."""

    def test_ret2csu_chain_function(self):
        """Test ret2csu_chain convenience function."""
        binary = MockBinary(bits=64, has_csu=True)

        chain = ret2csu_chain(
            binary,
            call_target=0x404018,
            arg1=0x1234,
        )

        self.assertIsInstance(chain, bytes)

    def test_optimize_rop_chain_function(self):
        """Test optimize_rop_chain convenience function."""
        binary = MockBinary(bits=64)

        operations = [
            ("set_rdi", 0x1234),
            ("syscall", None),
        ]

        chain = optimize_rop_chain(binary, operations)

        self.assertIsInstance(chain, bytes)


def run_tests():
    """Run all tests and return results."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_classes = [
        TestCSUGadgetInfo,
        TestRet2CSU,
        TestRet2dlresolve,
        TestROPOptimizer,
        TestChainMinimizer,
        TestStackPivot,
        TestGadgetTypes,
        TestConvenienceFunctions,
    ]

    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result


if __name__ == "__main__":
    run_tests()
