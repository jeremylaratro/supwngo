"""Tests for advanced bypass modules (CFI, CET)."""

import pytest
from unittest.mock import Mock, MagicMock, patch


class TestCFITypes:
    """Test CFI type definitions."""

    def test_cfi_type_enum(self):
        """Test CFIType enum values."""
        from supwngo.exploit.advanced_bypass.cfi import CFIType

        assert CFIType.NONE is not None
        assert CFIType.LLVM_CFI is not None
        assert CFIType.MS_CFG is not None
        assert CFIType.GCC_VTV is not None

    def test_indirect_call_site_dataclass(self):
        """Test IndirectCallSite dataclass."""
        from supwngo.exploit.advanced_bypass.cfi import IndirectCallSite, CFIType

        site = IndirectCallSite(
            address=0x401000,
            instruction="call rax",
            call_target_reg="rax",
            cfi_protected=True,
            cfi_type=CFIType.LLVM_CFI
        )

        assert site.address == 0x401000
        assert site.instruction == "call rax"
        assert site.call_target_reg == "rax"
        assert site.cfi_protected is True
        assert site.cfi_type == CFIType.LLVM_CFI

    def test_vtable_info_dataclass(self):
        """Test VTableInfo dataclass."""
        from supwngo.exploit.advanced_bypass.cfi import VTableInfo

        vtable = VTableInfo(
            address=0x404000,
            class_name="TestClass",
            method_count=3,
            methods=[
                (0x401100, "method1"),
                (0x401200, "method2"),
                (0x401300, "method3"),
            ]
        )

        assert vtable.address == 0x404000
        assert vtable.class_name == "TestClass"
        assert vtable.method_count == 3
        assert len(vtable.methods) == 3

    def test_coop_gadget_dataclass(self):
        """Test COOPGadget dataclass."""
        from supwngo.exploit.advanced_bypass.cfi import COOPGadget, VTableInfo

        vtable = VTableInfo(address=0x404000, method_count=1)
        gadget = COOPGadget(
            vtable=vtable,
            method_offset=0,
            method_address=0x401100,
            effect_type="call",
            controlls_rip=True
        )

        assert gadget.vtable.address == 0x404000
        assert gadget.method_offset == 0
        assert gadget.effect_type == "call"
        assert gadget.controlls_rip is True

    def test_cfi_info_dataclass(self):
        """Test CFIInfo dataclass."""
        from supwngo.exploit.advanced_bypass.cfi import CFIInfo, CFIType

        info = CFIInfo(
            detected=True,
            cfi_type=CFIType.LLVM_CFI_VCALL,
            cfi_version="1.0"
        )

        assert info.detected is True
        assert info.cfi_type == CFIType.LLVM_CFI_VCALL
        assert info.cfi_version == "1.0"
        assert len(info.indirect_calls) == 0
        assert len(info.vtables) == 0


class TestCFIAnalyzer:
    """Test CFI analysis functionality."""

    def test_analyzer_init(self):
        """Test CFIAnalyzer initialization."""
        from supwngo.exploit.advanced_bypass.cfi import CFIAnalyzer

        mock_binary = Mock()
        mock_binary.bits = 64
        mock_binary.elf = None

        analyzer = CFIAnalyzer(mock_binary)
        assert analyzer.binary == mock_binary

    def test_analyzer_no_cfi(self):
        """Test analyzer with no CFI protection."""
        from supwngo.exploit.advanced_bypass.cfi import CFIAnalyzer, CFIType

        mock_binary = Mock()
        mock_binary.bits = 64
        mock_binary.elf = None
        mock_binary.symbols = {}

        analyzer = CFIAnalyzer(mock_binary)
        info = analyzer.analyze()

        assert info.detected is False
        assert info.cfi_type == CFIType.NONE

    def test_detect_llvm_cfi_markers(self):
        """Test detection of LLVM CFI markers."""
        from supwngo.exploit.advanced_bypass.cfi import CFIAnalyzer, CFIType

        mock_binary = Mock()
        mock_binary.bits = 64
        mock_binary.symbols = {"__cfi_check": 0x401000}

        # Mock ELF
        mock_elf = MagicMock()
        mock_section = MagicMock()
        mock_section.name = ".text"
        mock_elf.iter_sections.return_value = [mock_section]
        mock_binary.elf = mock_elf

        analyzer = CFIAnalyzer(mock_binary)
        cfi_type = analyzer._detect_cfi_type()

        assert cfi_type == CFIType.LLVM_CFI


class TestCFIBypass:
    """Test CFI bypass functionality."""

    def test_bypass_init(self):
        """Test CFIBypass initialization."""
        from supwngo.exploit.advanced_bypass.cfi import CFIBypass, CFIInfo

        mock_binary = Mock()
        mock_binary.bits = 64
        mock_binary.elf = None
        mock_binary.symbols = {}

        cfi_info = CFIInfo(detected=False)
        bypass = CFIBypass(mock_binary, cfi_info)

        assert bypass.binary == mock_binary
        assert bypass.cfi_info == cfi_info

    def test_create_fake_vtable(self):
        """Test fake vtable creation."""
        from supwngo.exploit.advanced_bypass.cfi import CFIBypass, CFIInfo

        mock_binary = Mock()
        mock_binary.bits = 64
        mock_binary.elf = None
        mock_binary.symbols = {}

        cfi_info = CFIInfo(detected=False)
        bypass = CFIBypass(mock_binary, cfi_info)

        fake_vtable = bypass.create_fake_vtable(
            target_methods=[0x401000, 0x401100, 0x401200],
            writable_addr=0x602000
        )

        assert len(fake_vtable) == 24  # 3 * 8 bytes for 64-bit
        # Verify addresses are packed correctly
        import struct
        addr1 = struct.unpack("<Q", fake_vtable[0:8])[0]
        assert addr1 == 0x401000

    def test_generate_exploit_template(self):
        """Test exploit template generation."""
        from supwngo.exploit.advanced_bypass.cfi import CFIBypass, CFIInfo, CFIType

        mock_binary = Mock()
        mock_binary.bits = 64
        mock_binary.elf = None
        mock_binary.symbols = {}
        mock_binary.path = "/path/to/binary"

        cfi_info = CFIInfo(
            detected=True,
            cfi_type=CFIType.LLVM_CFI
        )
        bypass = CFIBypass(mock_binary, cfi_info)

        template = bypass.generate_exploit_template()

        assert "CFI Bypass Exploit Template" in template
        assert "LLVM_CFI" in template
        assert "COOP" in template


class TestCETTypes:
    """Test CET type definitions."""

    def test_cet_feature_enum(self):
        """Test CETFeature enum values."""
        from supwngo.exploit.advanced_bypass.cet import CETFeature

        assert CETFeature.NONE is not None
        assert CETFeature.SHADOW_STACK is not None
        assert CETFeature.IBT is not None
        assert CETFeature.SHADOW_STACK_AND_IBT is not None

    def test_cet_info_dataclass(self):
        """Test CETInfo dataclass."""
        from supwngo.exploit.advanced_bypass.cet import CETInfo, CETFeature

        info = CETInfo(
            detected=True,
            features=CETFeature.SHADOW_STACK_AND_IBT,
            shadow_stack_enabled=True,
            ibt_enabled=True,
            endbr_count=42
        )

        assert info.detected is True
        assert info.features == CETFeature.SHADOW_STACK_AND_IBT
        assert info.shadow_stack_enabled is True
        assert info.ibt_enabled is True
        assert info.endbr_count == 42

    def test_signal_based_bypass_dataclass(self):
        """Test SignalBasedBypass dataclass."""
        from supwngo.exploit.advanced_bypass.cet import SignalBasedBypass

        bypass = SignalBasedBypass(
            signal_number=11,
            handler_address=0x401000,
            can_corrupt_shadow_stack=True,
            exploitation_notes="SIGSEGV handler found"
        )

        assert bypass.signal_number == 11
        assert bypass.handler_address == 0x401000
        assert bypass.can_corrupt_shadow_stack is True

    def test_ibt_bypass_dataclass(self):
        """Test IBTBypass dataclass."""
        from supwngo.exploit.advanced_bypass.cet import IBTBypass

        bypass = IBTBypass(
            address=0x401000,
            instruction="endbr64",
            gadget_type="endbr64",
            following_instructions=["pop rdi", "ret"],
            useful_for="pop_rdi"
        )

        assert bypass.address == 0x401000
        assert bypass.gadget_type == "endbr64"
        assert bypass.useful_for == "pop_rdi"

    def test_shadow_stack_bypass_dataclass(self):
        """Test ShadowStackBypass dataclass."""
        from supwngo.exploit.advanced_bypass.cet import ShadowStackBypass

        bypass = ShadowStackBypass(
            technique="Signal Handler Manipulation",
            requirements=["Control signal handler"],
            success_rate="high",
            description="Corrupt signal frame"
        )

        assert bypass.technique == "Signal Handler Manipulation"
        assert bypass.success_rate == "high"


class TestCETAnalyzer:
    """Test CET analysis functionality."""

    def test_analyzer_init(self):
        """Test CETAnalyzer initialization."""
        from supwngo.exploit.advanced_bypass.cet import CETAnalyzer

        mock_binary = Mock()
        mock_binary.bits = 64
        mock_binary.elf = None

        analyzer = CETAnalyzer(mock_binary)
        assert analyzer.binary == mock_binary

    def test_analyzer_no_cet(self):
        """Test analyzer with no CET protection."""
        from supwngo.exploit.advanced_bypass.cet import CETAnalyzer, CETFeature

        mock_binary = Mock()
        mock_binary.bits = 64
        mock_binary.elf = None

        analyzer = CETAnalyzer(mock_binary)
        info = analyzer.analyze()

        assert info.detected is False
        assert info.features == CETFeature.NONE

    def test_endbr_bytes_constants(self):
        """Test ENDBR instruction byte constants."""
        from supwngo.exploit.advanced_bypass.cet import CETAnalyzer

        # ENDBR64: F3 0F 1E FA
        assert CETAnalyzer.ENDBR64_BYTES == bytes([0xf3, 0x0f, 0x1e, 0xfa])
        # ENDBR32: F3 0F 1E FB
        assert CETAnalyzer.ENDBR32_BYTES == bytes([0xf3, 0x0f, 0x1e, 0xfb])


class TestCETBypass:
    """Test CET bypass functionality."""

    def test_bypass_init(self):
        """Test CETBypass initialization."""
        from supwngo.exploit.advanced_bypass.cet import CETBypass, CETInfo

        mock_binary = Mock()
        mock_binary.bits = 64
        mock_binary.elf = None

        cet_info = CETInfo(detected=False)
        bypass = CETBypass(mock_binary, cet_info)

        assert bypass.binary == mock_binary
        assert bypass.cet_info == cet_info

    def test_signal_handler_bypass(self):
        """Test signal handler bypass generation."""
        from supwngo.exploit.advanced_bypass.cet import CETBypass, CETInfo

        mock_binary = Mock()
        mock_binary.bits = 64
        mock_binary.elf = None

        cet_info = CETInfo(
            detected=True,
            shadow_stack_enabled=True,
            signal_handlers=[0x401000]
        )
        bypass = CETBypass(mock_binary, cet_info)

        signal_bypass = bypass.signal_handler_bypass(signal_num=11)

        assert signal_bypass.signal_number == 11
        assert signal_bypass.handler_address == 0x401000
        assert signal_bypass.can_corrupt_shadow_stack is True

    def test_shadow_stack_techniques(self):
        """Test shadow stack technique listing."""
        from supwngo.exploit.advanced_bypass.cet import CETBypass, CETInfo

        mock_binary = Mock()
        mock_binary.bits = 64
        mock_binary.elf = None

        cet_info = CETInfo(detected=True, shadow_stack_enabled=True)
        bypass = CETBypass(mock_binary, cet_info)

        techniques = bypass.shadow_stack_techniques()

        assert len(techniques) >= 3  # At least signal, exception, race
        technique_names = [t.technique for t in techniques]
        assert "Signal Handler Manipulation" in technique_names
        assert "C++ Exception Handler" in technique_names
        assert "Shadow Stack Desynchronization" in technique_names

    def test_generate_strategy(self):
        """Test strategy generation."""
        from supwngo.exploit.advanced_bypass.cet import CETBypass, CETInfo, CETFeature

        mock_binary = Mock()
        mock_binary.bits = 64
        mock_binary.elf = None
        mock_binary.path = "/test/binary"

        cet_info = CETInfo(
            detected=True,
            features=CETFeature.SHADOW_STACK,
            shadow_stack_enabled=True,
            signal_handlers=[0x401000]
        )
        bypass = CETBypass(mock_binary, cet_info)

        strategy = bypass.generate_strategy()

        assert strategy.primary_technique == "signal_handler"
        assert strategy.reliability == "high"
        assert len(strategy.bypasses) > 0

    def test_no_cet_strategy(self):
        """Test strategy when no CET is present."""
        from supwngo.exploit.advanced_bypass.cet import CETBypass, CETInfo

        mock_binary = Mock()
        mock_binary.bits = 64
        mock_binary.elf = None
        mock_binary.path = "/test/binary"

        cet_info = CETInfo(detected=False)
        bypass = CETBypass(mock_binary, cet_info)

        strategy = bypass.generate_strategy()

        assert strategy.primary_technique == "none_needed"
        assert strategy.reliability == "high"


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_find_cfi_bypasses(self):
        """Test find_cfi_bypasses function."""
        from supwngo.exploit.advanced_bypass.cfi import find_cfi_bypasses

        mock_binary = Mock()
        mock_binary.bits = 64
        mock_binary.elf = None
        mock_binary.symbols = {}

        info = find_cfi_bypasses(mock_binary)

        assert info is not None
        assert hasattr(info, 'detected')
        assert hasattr(info, 'cfi_type')

    def test_analyze_cet_protection(self):
        """Test analyze_cet_protection function."""
        from supwngo.exploit.advanced_bypass.cet import analyze_cet_protection

        mock_binary = Mock()
        mock_binary.bits = 64
        mock_binary.elf = None

        info = analyze_cet_protection(mock_binary)

        assert info is not None
        assert hasattr(info, 'detected')
        assert hasattr(info, 'features')


class TestModuleImports:
    """Test that modules can be imported correctly."""

    def test_import_from_bypass_package(self):
        """Test imports from advanced_bypass package."""
        from supwngo.exploit.advanced_bypass import (
            CFIAnalyzer,
            CFIBypass,
            CFIType,
            CETAnalyzer,
            CETBypass,
            CETInfo,
        )

        assert CFIAnalyzer is not None
        assert CFIBypass is not None
        assert CFIType is not None
        assert CETAnalyzer is not None
        assert CETBypass is not None
        assert CETInfo is not None

    def test_import_from_exploit_package(self):
        """Test imports from main exploit package."""
        from supwngo.exploit import (
            CFIAnalyzer,
            CFIBypass,
            CFIType,
            find_cfi_bypasses,
            CETAnalyzer,
            CETBypass,
            analyze_cet_protection,
        )

        assert CFIAnalyzer is not None
        assert CFIBypass is not None
        assert CFIType is not None
        assert find_cfi_bypasses is not None
        assert CETAnalyzer is not None
        assert CETBypass is not None
        assert analyze_cet_protection is not None
