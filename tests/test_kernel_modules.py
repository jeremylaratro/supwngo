"""
Tests for kernel exploitation modules.
"""

import pytest
from supwngo.kernel import (
    KernelModule,
    KernelSymbols,
    SlabAllocator,
    SlabSpray,
    KernelROPBuilder,
    KernelROPChain,
    KernelGadget,
    KernelExploitTemplate,
    Ret2usr,
    Ret2usrPayload,
    ModprobeExploit,
    ModprobePayload,
    CorePatternExploit,
)
from supwngo.kernel.symbols import KernelSymbol
from supwngo.kernel.slab import SlabCache


class TestRet2usrPayload:
    """Test Ret2usrPayload dataclass."""

    def test_default_values(self):
        """Test default payload values."""
        payload = Ret2usrPayload()
        assert payload.shellcode == b""
        assert payload.shellcode_addr == 0
        assert payload.user_cs == 0x33
        assert payload.user_ss == 0x2b
        assert payload.user_rflags == 0x246

    def test_custom_values(self):
        """Test custom payload values."""
        payload = Ret2usrPayload(
            shellcode=b"\x90\x90",
            shellcode_addr=0x41414141,
            user_rip=0x42424242,
            user_rsp=0x43434343,
        )
        assert payload.shellcode == b"\x90\x90"
        assert payload.shellcode_addr == 0x41414141
        assert payload.user_rip == 0x42424242
        assert payload.user_rsp == 0x43434343


class TestKernelSymbols:
    """Test KernelSymbols class."""

    def test_default_initialization(self):
        """Test default initialization."""
        symbols = KernelSymbols()
        assert symbols.kernel_text_base == 0xffffffff81000000
        assert symbols.kaslr_enabled == True
        assert len(symbols.symbols) == 0

    def test_add_symbol(self):
        """Test adding a symbol."""
        symbols = KernelSymbols()
        sym = KernelSymbol(
            name="commit_creds",
            address=0xffffffff81073ad0,
            type="T",
        )
        symbols.symbols["commit_creds"] = sym
        assert "commit_creds" in symbols.symbols
        assert symbols.symbols["commit_creds"].address == 0xffffffff81073ad0


class TestKernelSymbol:
    """Test KernelSymbol dataclass."""

    def test_symbol_creation(self):
        """Test kernel symbol creation."""
        sym = KernelSymbol(
            name="commit_creds",
            address=0xffffffff81073ad0,
            type="T",
        )
        assert sym.name == "commit_creds"
        assert sym.address == 0xffffffff81073ad0
        assert sym.type == "T"


class TestKernelGadget:
    """Test KernelGadget dataclass."""

    def test_gadget_creation(self):
        """Test kernel gadget creation."""
        gadget = KernelGadget(
            address=0xffffffff81001234,
            instructions="pop rdi; ret",
            offset=0x1234,
        )
        assert gadget.address == 0xffffffff81001234
        assert gadget.instructions == "pop rdi; ret"
        assert gadget.offset == 0x1234

    def test_gadget_str(self):
        """Test gadget string representation."""
        gadget = KernelGadget(
            address=0xffffffff81001234,
            instructions="pop rdi; ret",
        )
        assert "pop rdi; ret" in str(gadget)


class TestKernelROPChain:
    """Test KernelROPChain class."""

    def test_empty_chain(self):
        """Test empty ROP chain."""
        chain = KernelROPChain()
        assert len(chain.gadgets) == 0

    def test_chain_add(self):
        """Test adding to chain."""
        chain = KernelROPChain()
        chain.add(0xffffffff81001234, "pop rdi; ret")
        assert len(chain.gadgets) == 1
        assert chain.gadgets[0] == (0xffffffff81001234, "pop rdi; ret")

    def test_chain_build(self):
        """Test building chain bytes."""
        chain = KernelROPChain()
        chain.add(0x41414141, "gadget1")
        chain.add(0x42424242, "gadget2")
        built = chain.build()
        assert len(built) == 16  # Two 8-byte addresses


class TestSlabCache:
    """Test SlabCache dataclass."""

    def test_slab_cache_creation(self):
        """Test slab cache creation."""
        cache = SlabCache(
            name="kmalloc-64",
            size=64,
            obj_per_slab=64,
        )
        assert cache.name == "kmalloc-64"
        assert cache.size == 64

    def test_slab_cache_with_structs(self):
        """Test slab cache with useful structures."""
        cache = SlabCache(
            name="kmalloc-64",
            size=64,
            useful_structs=["subprocess_info", "userfaultfd_ctx"],
        )
        assert "subprocess_info" in cache.useful_structs


class TestSlabAllocator:
    """Test SlabAllocator class."""

    def test_get_cache_for_size(self):
        """Test allocation size to cache mapping."""
        # get_cache_for_size returns SlabCache, not string
        cache = SlabAllocator.get_cache_for_size(17)
        assert cache is not None
        assert cache.name == "kmalloc-32"

    def test_get_cache_for_exact_size(self):
        """Test exact size to cache mapping."""
        cache = SlabAllocator.get_cache_for_size(64)
        assert cache is not None
        assert cache.name == "kmalloc-64"


class TestSlabSpray:
    """Test SlabSpray class."""

    def test_get_spray_for_cache(self):
        """Test getting spray code for cache."""
        spray_code = SlabSpray.get_spray_for_cache("kmalloc-256")
        assert spray_code is not None
        assert isinstance(spray_code, str)

    def test_get_all_spray_code(self):
        """Test getting all spray code."""
        all_code = SlabSpray.get_all_spray_code()
        assert all_code is not None
        assert isinstance(all_code, str)


class TestModprobePayload:
    """Test ModprobePayload dataclass."""

    def test_default_values(self):
        """Test default modprobe payload values."""
        payload = ModprobePayload()
        assert payload.new_path == "/tmp/x"
        assert payload.trigger_file == "/tmp/dummy"

    def test_custom_values(self):
        """Test custom payload values."""
        payload = ModprobePayload(
            new_path="/tmp/pwn.sh",
            script_content="#!/bin/sh\nid > /tmp/pwned",
        )
        assert payload.new_path == "/tmp/pwn.sh"
        assert "id > /tmp/pwned" in payload.script_content


class TestModprobeExploit:
    """Test ModprobeExploit class."""

    def test_initialization(self):
        """Test modprobe exploit initialization."""
        symbols = KernelSymbols()
        symbols.kernel_base = 0xffffffff81000000
        exploit = ModprobeExploit(symbols)
        assert exploit is not None
        assert exploit.symbols == symbols

    def test_payload_generation(self):
        """Test exploit payload generation."""
        symbols = KernelSymbols()
        symbols.kernel_base = 0xffffffff81000000
        exploit = ModprobeExploit(symbols)
        payload = exploit.generate_payload()
        assert payload is not None
        assert isinstance(payload, ModprobePayload)


class TestCorePatternExploit:
    """Test CorePatternExploit class."""

    def test_initialization(self):
        """Test core pattern exploit initialization."""
        symbols = KernelSymbols()
        symbols.kernel_base = 0xffffffff81000000
        exploit = CorePatternExploit(symbols)
        assert exploit is not None


class TestKernelExploitTemplate:
    """Test KernelExploitTemplate class."""

    def test_initialization(self):
        """Test template initialization."""
        template = KernelExploitTemplate()
        assert template is not None

    def test_generate_method_exists(self):
        """Test that generate method exists."""
        template = KernelExploitTemplate()
        # Template has generate_full_exploit method
        assert hasattr(template, 'generate_full_exploit') or hasattr(template, 'generate')


class TestRet2usr:
    """Test Ret2usr class."""

    def test_initialization(self):
        """Test ret2usr initialization."""
        symbols = KernelSymbols()
        symbols.kernel_base = 0xffffffff81000000
        ret2usr = Ret2usr(symbols)
        assert ret2usr is not None
        assert ret2usr.kernel_base == 0xffffffff81000000

    def test_check_protections(self):
        """Test protection checking."""
        symbols = KernelSymbols()
        symbols.kernel_base = 0xffffffff81000000
        ret2usr = Ret2usr(symbols)
        protections = ret2usr.check_protections()
        assert isinstance(protections, dict)
        assert "smep_enabled" in protections or "kaslr_enabled" in protections


class TestKernelROPBuilder:
    """Test KernelROPBuilder class."""

    def test_builder_initialization(self):
        """Test ROP builder initialization."""
        symbols = KernelSymbols()
        builder = KernelROPBuilder(symbols)
        assert builder is not None

    def test_full_privesc_chain_method(self):
        """Test build_full_privesc_chain method exists."""
        symbols = KernelSymbols()
        builder = KernelROPBuilder(symbols)
        assert hasattr(builder, 'build_full_privesc_chain')


class TestIntegration:
    """Integration tests for kernel modules."""

    def test_modprobe_exploit_workflow(self):
        """Test modprobe_path overwrite workflow."""
        symbols = KernelSymbols()
        symbols.kernel_base = 0xffffffff81000000

        exploit = ModprobeExploit(symbols)
        payload = exploit.generate_payload()
        assert payload is not None
        assert payload.new_path != ""

    def test_kernel_rop_builder_chain(self):
        """Test kernel ROP chain building."""
        symbols = KernelSymbols()
        symbols.kernel_base = 0xffffffff81000000

        builder = KernelROPBuilder(symbols)
        # Test that chain building works
        chain = KernelROPChain()
        chain.add(0xffffffff81001234, "pop rdi; ret")
        chain.add(0, "arg")
        chain.add(0xffffffff81073ad0, "prepare_kernel_cred")

        built = chain.build()
        assert len(built) == 24  # Three 8-byte addresses

    def test_slab_allocator_with_spray(self):
        """Test slab allocator with spray helper."""
        cache = SlabAllocator.get_cache_for_size(128)
        assert cache is not None
        assert cache.size == 128

        # SlabSpray provides static methods for getting spray code
        spray_code = SlabSpray.get_spray_for_cache(cache.name)
        assert spray_code is not None

    def test_ret2usr_protection_check(self):
        """Test ret2usr with protection checking."""
        symbols = KernelSymbols()
        symbols.kernel_base = 0xffffffff81000000

        ret2usr = Ret2usr(symbols)
        protections = ret2usr.check_protections()

        # Check returns dict with expected keys
        assert isinstance(protections, dict)
