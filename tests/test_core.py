"""Tests for core modules."""

import pytest
from pathlib import Path


class TestExploitContext:
    """Tests for ExploitContext."""

    def test_context_creation(self):
        """Test creating an exploit context."""
        from supwngo.core.context import ExploitContext

        ctx = ExploitContext()
        assert ctx.arch == "amd64"
        assert ctx.bits == 64
        assert ctx.binary is None

    def test_context_32bit(self):
        """Test 32-bit context."""
        from supwngo.core.context import ExploitContext

        ctx = ExploitContext(arch="i386", bits=32)
        assert ctx.arch == "i386"
        assert ctx.bits == 32

    def test_add_leak(self):
        """Test adding leaks."""
        from supwngo.core.context import ExploitContext

        ctx = ExploitContext()
        ctx.add_leak("libc_puts", 0x7ffff7a62000)
        assert "libc_puts" in ctx.leaks
        assert ctx.leaks["libc_puts"] == 0x7ffff7a62000


class TestProtections:
    """Tests for protection detection."""

    def test_protections_dataclass(self):
        """Test Protections dataclass."""
        from supwngo.core.context import Protections

        prots = Protections(
            canary=True,
            nx=True,
            pie=False,
            relro="Partial RELRO",
            aslr=True,
        )
        assert prots.canary is True
        assert prots.nx is True
        assert prots.pie is False
        assert prots.relro == "Partial RELRO"


class TestHelpers:
    """Tests for helper functions."""

    def test_p64(self):
        """Test p64 packing."""
        from supwngo.utils.helpers import p64

        assert p64(0x41414141) == b"AAAA\x00\x00\x00\x00"
        assert len(p64(0)) == 8

    def test_u64(self):
        """Test u64 unpacking."""
        from supwngo.utils.helpers import u64

        assert u64(b"AAAAAAAA") == 0x4141414141414141

    def test_p32(self):
        """Test p32 packing."""
        from supwngo.utils.helpers import p32

        assert p32(0x41414141) == b"AAAA"
        assert len(p32(0)) == 4

    def test_u32(self):
        """Test u32 unpacking."""
        from supwngo.utils.helpers import u32

        assert u32(b"AAAA") == 0x41414141

    def test_cyclic(self):
        """Test cyclic pattern generation."""
        from supwngo.utils.helpers import cyclic, cyclic_find

        pattern = cyclic(100)
        assert len(pattern) == 100
        # Each 4-byte sequence should be unique
        assert b"aaaa" in pattern

    def test_cyclic_find(self):
        """Test finding offset in cyclic pattern."""
        from supwngo.utils.helpers import cyclic, cyclic_find

        pattern = cyclic(200)
        # Find a known subsequence
        offset = cyclic_find(pattern[44:48])
        assert offset == 44


class TestDatabase:
    """Tests for database operations."""

    def test_database_creation(self, tmp_path):
        """Test creating a database."""
        from supwngo.core.database import Database

        db_path = tmp_path / "test.db"
        db = Database(str(db_path))
        assert db_path.exists()

    def test_store_and_get_binary(self, tmp_path):
        """Test storing and retrieving binary info."""
        from supwngo.core.database import Database

        db_path = tmp_path / "test.db"
        db = Database(str(db_path))

        binary_id = db.save_binary_analysis(
            path="/test/binary",
            sha256="abc123",
            arch="amd64",
            bits=64,
            protections={"nx": True, "canary": True},
            analysis_data={"test": "data"},
        )

        info = db.get_binary_analysis("abc123")
        assert info is not None
        assert info["path"] == "/test/binary"
        assert info["arch"] == "amd64"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
