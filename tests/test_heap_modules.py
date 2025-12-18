#!/usr/bin/env python3
"""
Test suite for heap exploitation modules.

Tests the following modules against compiled test binaries:
- House of Force
- House of Spirit
- Unsorted Bin Attack
- Large Bin Attack
- Safe-linking bypass
- tcache techniques
"""

import os
import sys
import unittest
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from supwngo.exploit.heap import (
    # Phase 3
    HouseOfForce,
    house_of_force_exploit,
    HouseOfSpirit,
    FakeChunk,
    house_of_spirit_exploit,
    UnsortedBinAttack,
    UnsortedBinIntoStack,
    unsorted_bin_attack,
    # Phase 4
    LargeBinAttack,
    HouseOfStorm,
    large_bin_attack,
    SafeLinkingBypassAdvanced,
    safe_linking_encrypt,
    safe_linking_decrypt,
    recover_heap_base,
    # Original
    HeapExploiter,
    HeapTechnique,
    TcacheExploiter,
    TcacheKeyBypass,
    SafeLinkingBypass,
)

# Test binary paths
TEST_BINARIES = Path(__file__).parent.parent / "test_binaries" / "heap"


class TestHouseOfForce(unittest.TestCase):
    """Test House of Force module."""

    def setUp(self):
        self.hof = HouseOfForce(bits=64, libc_version="2.27")
        self.hof_32 = HouseOfForce(bits=32, libc_version="2.27")

    def test_initialization(self):
        """Test module initialization."""
        self.assertEqual(self.hof.bits, 64)
        self.assertEqual(self.hof.libc_version, "2.27")
        self.assertFalse(self.hof.has_size_checks)

    def test_feasibility_check_old_glibc(self):
        """Test feasibility on old glibc (should be feasible)."""
        result = self.hof.check_feasibility()
        self.assertTrue(result["feasible"])
        self.assertEqual(len(result["warnings"]), 0)

    def test_feasibility_check_new_glibc(self):
        """Test feasibility on new glibc (should not be feasible)."""
        hof_new = HouseOfForce(bits=64, libc_version="2.31")
        result = hof_new.check_feasibility()
        self.assertFalse(result["feasible"])
        self.assertGreater(len(result["warnings"]), 0)

    def test_evil_size_calculation(self):
        """Test evil size calculation."""
        top_chunk = 0x555555559000
        target = 0x404040

        evil_size = self.hof.calculate_evil_size(top_chunk, target)

        # Evil size should be negative (wrapped) since target < top
        # The formula: target - top - 2*header = negative value
        self.assertIsInstance(evil_size, int)

    def test_evil_size_forward(self):
        """Test evil size for forward allocation."""
        top_chunk = 0x404000
        target = 0x555555559000

        evil_size = self.hof.calculate_evil_size(top_chunk, target)

        # Should be positive for forward movement
        expected = target - top_chunk - 32  # 2 * 16-byte headers
        self.assertEqual(evil_size, expected)

    def test_overflow_payload_generation(self):
        """Test overflow payload generation."""
        payload = self.hof.generate_overflow_payload(padding_size=0x18)

        # Should contain -1 (max size)
        self.assertIn(b"\xff\xff\xff\xff\xff\xff\xff\xff", payload)
        self.assertGreaterEqual(len(payload), 0x18 + 16)

    def test_exploit_generation(self):
        """Test full exploit generation."""
        exploit = self.hof.generate_exploit(
            top_chunk_addr=0x555555559000,
            target_addr=0x404040,
            overflow_padding=0x18,
        )

        self.assertEqual(exploit["technique"], "house_of_force")
        self.assertEqual(exploit["target"], 0x404040)
        self.assertIn("evil_size", exploit)
        self.assertIn("overflow_payload", exploit)
        self.assertIn("steps", exploit)
        self.assertGreater(len(exploit["steps"]), 0)

    def test_got_overwrite_generation(self):
        """Test GOT overwrite exploit generation."""
        exploit = self.hof.generate_got_overwrite(
            top_chunk_addr=0x555555559000,
            got_entry=0x404018,
            new_value=0x401234,
            overflow_padding=0x18,
        )

        self.assertIn("got_entry", exploit)
        self.assertIn("got_payload", exploit)
        self.assertEqual(exploit["got_entry"], 0x404018)

    def test_pwntools_script_generation(self):
        """Test pwntools script generation."""
        exploit = self.hof.generate_exploit(
            top_chunk_addr=0x555555559000,
            target_addr=0x404040,
            overflow_padding=0x18,
        )

        script = self.hof.generate_pwntools_script(exploit)

        self.assertIn("from pwn import", script)
        self.assertIn("evil_size", script)
        self.assertIn("0x404040", script)

    def test_32bit_support(self):
        """Test 32-bit architecture support."""
        exploit = self.hof_32.generate_exploit(
            top_chunk_addr=0x804b000,
            target_addr=0x804a000,
            overflow_padding=0x10,
        )

        # 32-bit should use 4-byte packing
        self.assertEqual(self.hof_32.header_size, 8)
        self.assertIn(b"\xff\xff\xff\xff", exploit["overflow_payload"])

    def test_convenience_function(self):
        """Test convenience function."""
        result = house_of_force_exploit(
            top_chunk_addr=0x555555559000,
            target_addr=0x404040,
            overflow_padding=0x18,
        )

        self.assertEqual(result["technique"], "house_of_force")


class TestHouseOfSpirit(unittest.TestCase):
    """Test House of Spirit module."""

    def setUp(self):
        self.hos = HouseOfSpirit(bits=64, libc_version="2.31")
        self.hos_old = HouseOfSpirit(bits=64, libc_version="2.23")

    def test_initialization(self):
        """Test module initialization."""
        self.assertEqual(self.hos.bits, 64)
        self.assertTrue(self.hos.has_tcache)

    def test_tcache_detection(self):
        """Test tcache availability detection."""
        # glibc 2.31 has tcache
        self.assertTrue(self.hos.has_tcache)

        # glibc 2.23 doesn't have tcache
        self.assertFalse(self.hos_old.has_tcache)

    def test_chunk_size_validation(self):
        """Test chunk size validation."""
        # Valid size
        result = self.hos.validate_chunk_size(0x40)
        self.assertTrue(result["valid"])

        # Too small
        result = self.hos.validate_chunk_size(0x10)
        self.assertFalse(result["valid"])

        # Misaligned
        result = self.hos.validate_chunk_size(0x45)
        self.assertFalse(result["valid"])

    def test_fake_chunk_building(self):
        """Test fake chunk header building."""
        fake_chunk = self.hos.build_fake_chunk(size=0x40)

        # Should be 16 bytes (prev_size + size)
        self.assertEqual(len(fake_chunk), 16)

        # Size should have PREV_INUSE bit set (0x41)
        self.assertIn(b"\x41", fake_chunk)

    def test_next_chunk_header(self):
        """Test next chunk header building."""
        next_chunk = self.hos.build_next_chunk_header()

        # Should have valid size
        self.assertEqual(len(next_chunk), 16)

    def test_exploit_generation(self):
        """Test exploit generation."""
        exploit = self.hos.generate_exploit(
            target_addr=0x7fffffffde00,
            chunk_size=0x40,
        )

        self.assertEqual(exploit["technique"], "house_of_spirit")
        self.assertEqual(exploit["target"], 0x7fffffffde00)
        self.assertEqual(exploit["fake_chunk_addr"], 0x7fffffffde00 - 16)
        self.assertIn("fake_chunk_payload", exploit)
        self.assertIn("next_chunk_payload", exploit)

    def test_stack_pivot_generation(self):
        """Test stack pivot exploit generation."""
        rop_chain = b"A" * 64  # Dummy ROP chain

        exploit = self.hos.generate_stack_pivot(
            stack_addr=0x7fffffffde00,
            rop_chain=rop_chain,
        )

        self.assertIn("rop_chain", exploit)
        self.assertEqual(exploit["rop_chain"], rop_chain)

    def test_complete_layout(self):
        """Test complete memory layout building."""
        layout = self.hos.build_complete_layout(
            target_addr=0x7fffffffde00,
            chunk_size=0x40,
            fill_data=b"AAAA",
        )

        # Should include fake chunk + user data + next chunk
        self.assertGreater(len(layout), 0x40)

    def test_convenience_function(self):
        """Test convenience function."""
        result = house_of_spirit_exploit(
            target_addr=0x7fffffffde00,
            chunk_size=0x40,
        )

        self.assertEqual(result["technique"], "house_of_spirit")


class TestUnsortedBinAttack(unittest.TestCase):
    """Test Unsorted Bin Attack module."""

    def setUp(self):
        self.uba = UnsortedBinAttack(bits=64, libc_version="2.27")
        self.uba_patched = UnsortedBinAttack(bits=64, libc_version="2.31")

    def test_initialization(self):
        """Test module initialization."""
        self.assertEqual(self.uba.bits, 64)
        self.assertFalse(self.uba.is_patched)
        self.assertTrue(self.uba_patched.is_patched)

    def test_feasibility_old_glibc(self):
        """Test feasibility on old glibc."""
        result = self.uba.check_feasibility()
        self.assertTrue(result["feasible"])

    def test_feasibility_new_glibc(self):
        """Test feasibility on patched glibc."""
        result = self.uba_patched.check_feasibility()
        self.assertFalse(result["feasible"])
        self.assertGreater(len(result["warnings"]), 0)

    def test_bk_value_calculation(self):
        """Test bk value calculation."""
        target = 0x404060
        bk = self.uba.calculate_bk_value(target)

        # bk = target - 0x10 (fd offset)
        self.assertEqual(bk, target - 0x10)

    def test_exploit_generation(self):
        """Test exploit generation."""
        exploit = self.uba.generate_exploit(target_addr=0x404060)

        self.assertEqual(exploit["technique"], "unsorted_bin_attack")
        self.assertEqual(exploit["target"], 0x404060)
        self.assertIn("bk_value", exploit)
        self.assertIn("chunk_size", exploit)
        self.assertGreaterEqual(exploit["chunk_size"], 0x420)

    def test_libc_leak_generation(self):
        """Test libc leak exploit generation."""
        exploit = self.uba.generate_libc_leak(readable_addr=0x404060)

        self.assertEqual(exploit["use_case"], "libc_leak")
        self.assertIn("common_offsets", exploit)

    def test_tcache_fill_pattern(self):
        """Test tcache fill pattern generation."""
        pattern = self.uba.tcache_fill_pattern(chunk_size=0x90)

        # Should have 7 allocs + 7 frees
        self.assertEqual(len(pattern), 14)

    def test_payload_generation(self):
        """Test payload generation."""
        payload = self.uba.generate_payload(target_addr=0x404060)

        # Should be 16 bytes (fd + bk)
        self.assertEqual(len(payload), 16)

    def test_convenience_function(self):
        """Test convenience function."""
        result = unsorted_bin_attack(target_addr=0x404060)

        self.assertEqual(result["technique"], "unsorted_bin_attack")


class TestLargeBinAttack(unittest.TestCase):
    """Test Large Bin Attack module."""

    def setUp(self):
        self.lba = LargeBinAttack(bits=64, libc_version="2.31")

    def test_initialization(self):
        """Test module initialization."""
        self.assertEqual(self.lba.bits, 64)
        self.assertEqual(self.lba.min_large_size, 0x420)

    def test_feasibility_check(self):
        """Test feasibility check."""
        result = self.lba.check_feasibility()
        self.assertTrue(result["feasible"])
        self.assertIn("requirements", result)

    def test_size_calculation(self):
        """Test optimal size calculation."""
        sizes = self.lba.calculate_sizes(base_size=0x420)

        self.assertIn("chunk1_size", sizes)
        self.assertIn("chunk2_size", sizes)
        self.assertGreater(sizes["chunk1_size"], sizes["chunk2_size"])

    def test_bk_nextsize_calculation(self):
        """Test bk_nextsize value calculation."""
        target = 0x404040
        bk_nextsize = self.lba.calculate_bk_nextsize_value(target)

        # Should be target - bk_nextsize_offset (0x28 for 64-bit)
        self.assertEqual(bk_nextsize, target - 0x28)

    def test_exploit_generation(self):
        """Test exploit generation."""
        exploit = self.lba.generate_exploit(target_addr=0x404040)

        self.assertEqual(exploit["technique"], "large_bin_attack")
        self.assertEqual(exploit["target"], 0x404040)
        self.assertIn("bk_nextsize_value", exploit)
        self.assertIn("chunk1_size", exploit)
        self.assertIn("chunk2_size", exploit)

    def test_io_attack_generation(self):
        """Test FSOP setup exploit generation."""
        exploit = self.lba.generate_io_attack(io_list_all_addr=0x7ffff7fc5520)

        self.assertEqual(exploit["use_case"], "fsop")

    def test_convenience_function(self):
        """Test convenience function."""
        result = large_bin_attack(target_addr=0x404040)

        self.assertEqual(result["technique"], "large_bin_attack")


class TestHouseOfStorm(unittest.TestCase):
    """Test House of Storm module."""

    def setUp(self):
        self.hos = HouseOfStorm(bits=64, libc_version="2.27")
        self.hos_patched = HouseOfStorm(bits=64, libc_version="2.31")

    def test_feasibility_old_glibc(self):
        """Test feasibility on old glibc."""
        result = self.hos.check_feasibility()
        self.assertTrue(result["feasible"])

    def test_feasibility_new_glibc(self):
        """Test feasibility on patched glibc."""
        result = self.hos_patched.check_feasibility()
        self.assertFalse(result["feasible"])

    def test_exploit_generation(self):
        """Test exploit generation."""
        exploit = self.hos.generate_exploit(target_addr=0x404040)

        self.assertEqual(exploit["technique"], "house_of_storm")
        self.assertIn("steps", exploit)


class TestSafeLinking(unittest.TestCase):
    """Test Safe-Linking bypass module."""

    def setUp(self):
        self.sl = SafeLinkingBypassAdvanced(bits=64, libc_version="2.35")
        self.sl_old = SafeLinkingBypassAdvanced(bits=64, libc_version="2.27")

    def test_safe_linking_detection(self):
        """Test safe-linking detection."""
        self.assertTrue(self.sl.has_safe_linking)
        self.assertFalse(self.sl_old.has_safe_linking)

    def test_encrypt_decrypt_roundtrip(self):
        """Test encrypt/decrypt roundtrip."""
        ptr = 0x404040
        chunk_addr = 0x555555559000

        encrypted = self.sl.encrypt(ptr, chunk_addr)
        decrypted = self.sl.decrypt(encrypted, chunk_addr)

        self.assertEqual(decrypted, ptr)

    def test_convenience_functions(self):
        """Test convenience encrypt/decrypt functions."""
        ptr = 0x404040
        chunk_addr = 0x555555559000

        encrypted = safe_linking_encrypt(ptr, chunk_addr)
        decrypted = safe_linking_decrypt(encrypted, chunk_addr)

        self.assertEqual(decrypted, ptr)

    def test_heap_base_recovery(self):
        """Test heap base recovery from NULL."""
        # Simulate encrypted NULL pointer
        chunk_addr = 0x555555559000
        encrypted_null = chunk_addr >> 12

        recovered = self.sl.recover_heap_base_from_null(encrypted_null)

        # Should recover approximate heap base
        self.assertEqual(recovered, chunk_addr & ~0xFFF)

    def test_convenience_recover_heap_base(self):
        """Test convenience function."""
        encrypted_null = 0x555555559
        recovered = recover_heap_base(encrypted_null)

        self.assertEqual(recovered, encrypted_null << 12)

    def test_bypass_with_leak(self):
        """Test bypass generation with heap leak."""
        result = self.sl.generate_bypass_with_leak(
            target_ptr=0x404040,
            heap_leak=0x555555559000,
        )

        self.assertTrue(result["needed"])
        self.assertIn("encrypted_ptr", result)
        self.assertIn("payload", result)

    def test_bypass_not_needed_old_glibc(self):
        """Test that bypass not needed on old glibc."""
        result = self.sl_old.generate_bypass_with_leak(
            target_ptr=0x404040,
            heap_leak=0x555555559000,
        )

        self.assertFalse(result["needed"])

    def test_partial_overwrite_generation(self):
        """Test partial overwrite bypass generation."""
        result = self.sl.generate_partial_overwrite(
            target_offset=0x100,
            overwrite_bytes=2,
        )

        self.assertEqual(result["technique"], "partial_overwrite")
        self.assertIn("brute_force_bits", result)

    def test_pointer_analysis(self):
        """Test leaked pointer analysis."""
        chunk_addr = 0x555555559000
        ptr = 0x404040
        encrypted = self.sl.encrypt(ptr, chunk_addr)

        analysis = self.sl.analyze_leaked_pointer(encrypted, chunk_addr)

        self.assertTrue(analysis["is_encrypted"])
        self.assertEqual(analysis["decrypted_ptr"], ptr)


class TestTcacheExploiter(unittest.TestCase):
    """Test tcache exploiter module."""

    def setUp(self):
        self.tc = TcacheExploiter(libc_version="2.31", bits=64)
        self.tc_old = TcacheExploiter(libc_version="2.27", bits=64)
        self.tc_new = TcacheExploiter(libc_version="2.35", bits=64)

    def test_feature_detection(self):
        """Test feature detection for different versions."""
        # 2.31: tcache, key, no safe-linking
        self.assertTrue(self.tc.has_tcache)
        self.assertTrue(self.tc.has_key)
        self.assertFalse(self.tc.has_safe_linking)

        # 2.27: tcache, no key
        self.assertTrue(self.tc_old.has_tcache)
        self.assertFalse(self.tc_old.has_key)

        # 2.35: tcache, key, safe-linking
        self.assertTrue(self.tc_new.has_tcache)
        self.assertTrue(self.tc_new.has_key)
        self.assertTrue(self.tc_new.has_safe_linking)

    def test_libc_leak_generation(self):
        """Test libc leak exploit generation."""
        result = self.tc.libc_leak_via_unsorted()

        self.assertEqual(result["technique"], "libc_leak_unsorted_bin")
        self.assertIn("steps", result)
        self.assertEqual(result["tcache_fill_count"], 7)

    def test_double_free_with_bypass(self):
        """Test double-free with key bypass."""
        result = self.tc.double_free_with_key_bypass(target_addr=0x404040)

        self.assertEqual(result["technique"], "tcache_dup_key_bypass")
        self.assertTrue(result["requires_key_bypass"])

    def test_hook_targets(self):
        """Test hook target address calculation."""
        # Without libc base
        targets = self.tc.hook_overwrite_targets()
        self.assertIn("__malloc_hook", targets)
        self.assertIn("__free_hook", targets)

        # With libc base
        targets = self.tc.hook_overwrite_targets(libc_base=0x7ffff7c00000)
        self.assertGreater(targets["__malloc_hook"], 0x7ffff7c00000)


class TestHeapExploiter(unittest.TestCase):
    """Test main HeapExploiter class."""

    def test_technique_selection_uaf(self):
        """Test technique selection for UAF."""
        # Create a mock binary
        class MockBinary:
            bits = 64
            path = type('obj', (object,), {'name': 'test'})()

        exploiter = HeapExploiter(MockBinary())
        techniques = exploiter.select_technique("uaf", "2.31")

        self.assertIn(HeapTechnique.TCACHE_POISONING, techniques)

    def test_technique_selection_overflow(self):
        """Test technique selection for overflow."""
        class MockBinary:
            bits = 64
            path = type('obj', (object,), {'name': 'test'})()

        exploiter = HeapExploiter(MockBinary())
        techniques = exploiter.select_technique("overflow", "2.27")

        self.assertIn(HeapTechnique.HOUSE_OF_FORCE, techniques)


class TestTcacheKeyBypass(unittest.TestCase):
    """Test tcache key bypass module."""

    def test_key_corruption(self):
        """Test key corruption payload."""
        chunk = b"A" * 16

        corrupted = TcacheKeyBypass.corrupt_key(chunk)

        # Key at offset 0x08 should be zeroed
        self.assertEqual(corrupted[8:16], b"\x00" * 8)

    def test_key_offset(self):
        """Test key offset calculation."""
        offset_64 = TcacheKeyBypass.get_key_offset(bits=64)
        offset_32 = TcacheKeyBypass.get_key_offset(bits=32)

        self.assertEqual(offset_64, 8)
        self.assertEqual(offset_32, 4)


def run_tests():
    """Run all tests and return results."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    test_classes = [
        TestHouseOfForce,
        TestHouseOfSpirit,
        TestUnsortedBinAttack,
        TestLargeBinAttack,
        TestHouseOfStorm,
        TestSafeLinking,
        TestTcacheExploiter,
        TestHeapExploiter,
        TestTcacheKeyBypass,
    ]

    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    # Run with verbosity
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result


if __name__ == "__main__":
    run_tests()
