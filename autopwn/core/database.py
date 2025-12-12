"""
Database for caching analysis results, gadgets, and exploit attempts.
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

from autopwn.utils.logging import get_logger

logger = get_logger(__name__)


class Database:
    """
    SQLite database for persisting AutoPwn analysis results.

    Caches:
    - Binary analysis results
    - ROP gadgets
    - Crash information
    - Exploit attempts and results
    - Libc identification
    """

    def __init__(self, db_path: str = "~/.autopwn/autopwn.db"):
        """
        Initialize database.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(os.path.expanduser(db_path))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._connection() as conn:
            conn.executescript("""
                -- Binary analysis cache
                CREATE TABLE IF NOT EXISTS binaries (
                    id INTEGER PRIMARY KEY,
                    path TEXT NOT NULL,
                    sha256 TEXT UNIQUE NOT NULL,
                    arch TEXT,
                    bits INTEGER,
                    protections TEXT,  -- JSON
                    analysis_data TEXT,  -- JSON
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                -- ROP gadgets cache
                CREATE TABLE IF NOT EXISTS gadgets (
                    id INTEGER PRIMARY KEY,
                    binary_sha256 TEXT NOT NULL,
                    address INTEGER NOT NULL,
                    instructions TEXT NOT NULL,
                    gadget_type TEXT,
                    regs_modified TEXT,  -- JSON list
                    regs_controlled TEXT,  -- JSON list
                    stack_change INTEGER,
                    FOREIGN KEY (binary_sha256) REFERENCES binaries(sha256),
                    UNIQUE(binary_sha256, address)
                );

                -- Crash information
                CREATE TABLE IF NOT EXISTS crashes (
                    id INTEGER PRIMARY KEY,
                    binary_sha256 TEXT NOT NULL,
                    crash_hash TEXT UNIQUE NOT NULL,
                    input_data BLOB NOT NULL,
                    crash_address INTEGER,
                    crash_type TEXT,
                    registers TEXT,  -- JSON
                    backtrace TEXT,  -- JSON
                    exploitability TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (binary_sha256) REFERENCES binaries(sha256)
                );

                -- Exploit attempts
                CREATE TABLE IF NOT EXISTS exploits (
                    id INTEGER PRIMARY KEY,
                    binary_sha256 TEXT NOT NULL,
                    crash_id INTEGER,
                    technique TEXT NOT NULL,
                    payload BLOB,
                    script TEXT,
                    success INTEGER DEFAULT 0,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (binary_sha256) REFERENCES binaries(sha256),
                    FOREIGN KEY (crash_id) REFERENCES crashes(id)
                );

                -- Libc database cache
                CREATE TABLE IF NOT EXISTS libcs (
                    id INTEGER PRIMARY KEY,
                    libc_id TEXT UNIQUE NOT NULL,
                    version TEXT,
                    symbols TEXT,  -- JSON
                    path TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                -- Symbol cache for fast lookup
                CREATE TABLE IF NOT EXISTS symbols (
                    id INTEGER PRIMARY KEY,
                    binary_sha256 TEXT NOT NULL,
                    name TEXT NOT NULL,
                    address INTEGER NOT NULL,
                    type TEXT,
                    FOREIGN KEY (binary_sha256) REFERENCES binaries(sha256),
                    UNIQUE(binary_sha256, name, address)
                );

                -- Create indexes
                CREATE INDEX IF NOT EXISTS idx_gadgets_binary ON gadgets(binary_sha256);
                CREATE INDEX IF NOT EXISTS idx_crashes_binary ON crashes(binary_sha256);
                CREATE INDEX IF NOT EXISTS idx_symbols_binary ON symbols(binary_sha256);
                CREATE INDEX IF NOT EXISTS idx_gadgets_type ON gadgets(gadget_type);
            """)
            logger.debug(f"Database initialized at {self.db_path}")

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for database connections."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    # Binary analysis methods
    def save_binary_analysis(
        self,
        path: str,
        sha256: str,
        arch: str,
        bits: int,
        protections: Dict[str, Any],
        analysis_data: Dict[str, Any],
    ) -> int:
        """
        Save binary analysis results.

        Args:
            path: Binary file path
            sha256: Binary SHA256 hash
            arch: Architecture string
            bits: Bit width
            protections: Protection dictionary
            analysis_data: Additional analysis data

        Returns:
            Database row ID
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT OR REPLACE INTO binaries
                (path, sha256, arch, bits, protections, analysis_data, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    path,
                    sha256,
                    arch,
                    bits,
                    json.dumps(protections),
                    json.dumps(analysis_data),
                    datetime.now().isoformat(),
                ),
            )
            return cursor.lastrowid

    def get_binary_analysis(self, sha256: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached binary analysis.

        Args:
            sha256: Binary SHA256 hash

        Returns:
            Analysis data dict or None
        """
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM binaries WHERE sha256 = ?",
                (sha256,),
            ).fetchone()

            if row:
                return {
                    "path": row["path"],
                    "sha256": row["sha256"],
                    "arch": row["arch"],
                    "bits": row["bits"],
                    "protections": json.loads(row["protections"]),
                    "analysis_data": json.loads(row["analysis_data"]),
                }
            return None

    # Gadget caching methods
    def save_gadgets(
        self,
        binary_sha256: str,
        gadgets: List[Dict[str, Any]],
    ) -> int:
        """
        Save ROP gadgets for a binary.

        Args:
            binary_sha256: Binary SHA256 hash
            gadgets: List of gadget dictionaries

        Returns:
            Number of gadgets saved
        """
        with self._connection() as conn:
            # Clear existing gadgets
            conn.execute(
                "DELETE FROM gadgets WHERE binary_sha256 = ?",
                (binary_sha256,),
            )

            # Insert new gadgets
            for gadget in gadgets:
                conn.execute(
                    """
                    INSERT INTO gadgets
                    (binary_sha256, address, instructions, gadget_type,
                     regs_modified, regs_controlled, stack_change)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        binary_sha256,
                        gadget.get("address", 0),
                        gadget.get("instructions", ""),
                        gadget.get("type", ""),
                        json.dumps(gadget.get("regs_modified", [])),
                        json.dumps(gadget.get("regs_controlled", [])),
                        gadget.get("stack_change", 0),
                    ),
                )

            return len(gadgets)

    def get_gadgets(
        self,
        binary_sha256: str,
        gadget_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve cached gadgets.

        Args:
            binary_sha256: Binary SHA256 hash
            gadget_type: Optional filter by gadget type

        Returns:
            List of gadget dictionaries
        """
        with self._connection() as conn:
            if gadget_type:
                rows = conn.execute(
                    """
                    SELECT * FROM gadgets
                    WHERE binary_sha256 = ? AND gadget_type = ?
                    ORDER BY address
                    """,
                    (binary_sha256, gadget_type),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM gadgets
                    WHERE binary_sha256 = ?
                    ORDER BY address
                    """,
                    (binary_sha256,),
                ).fetchall()

            return [
                {
                    "address": row["address"],
                    "instructions": row["instructions"],
                    "type": row["gadget_type"],
                    "regs_modified": json.loads(row["regs_modified"]),
                    "regs_controlled": json.loads(row["regs_controlled"]),
                    "stack_change": row["stack_change"],
                }
                for row in rows
            ]

    # Crash caching methods
    def save_crash(
        self,
        binary_sha256: str,
        crash_hash: str,
        input_data: bytes,
        crash_address: int,
        crash_type: str,
        registers: Dict[str, int],
        backtrace: List[str],
        exploitability: str,
    ) -> int:
        """
        Save crash information.

        Args:
            binary_sha256: Binary SHA256 hash
            crash_hash: Unique crash identifier
            input_data: Input that caused crash
            crash_address: Address of crash
            crash_type: Type of crash (SIGSEGV, etc.)
            registers: Register state at crash
            backtrace: Stack backtrace
            exploitability: Exploitability rating

        Returns:
            Database row ID
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT OR REPLACE INTO crashes
                (binary_sha256, crash_hash, input_data, crash_address,
                 crash_type, registers, backtrace, exploitability)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    binary_sha256,
                    crash_hash,
                    input_data,
                    crash_address,
                    crash_type,
                    json.dumps(registers),
                    json.dumps(backtrace),
                    exploitability,
                ),
            )
            return cursor.lastrowid

    def get_crashes(
        self,
        binary_sha256: str,
        exploitability: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve crashes for a binary.

        Args:
            binary_sha256: Binary SHA256 hash
            exploitability: Optional filter by exploitability

        Returns:
            List of crash dictionaries
        """
        with self._connection() as conn:
            if exploitability:
                rows = conn.execute(
                    """
                    SELECT * FROM crashes
                    WHERE binary_sha256 = ? AND exploitability = ?
                    ORDER BY created_at DESC
                    """,
                    (binary_sha256, exploitability),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM crashes
                    WHERE binary_sha256 = ?
                    ORDER BY created_at DESC
                    """,
                    (binary_sha256,),
                ).fetchall()

            return [
                {
                    "id": row["id"],
                    "crash_hash": row["crash_hash"],
                    "input_data": row["input_data"],
                    "crash_address": row["crash_address"],
                    "crash_type": row["crash_type"],
                    "registers": json.loads(row["registers"]),
                    "backtrace": json.loads(row["backtrace"]),
                    "exploitability": row["exploitability"],
                }
                for row in rows
            ]

    # Exploit methods
    def save_exploit(
        self,
        binary_sha256: str,
        technique: str,
        payload: bytes,
        script: str,
        success: bool,
        crash_id: Optional[int] = None,
        notes: str = "",
    ) -> int:
        """
        Save exploit attempt.

        Args:
            binary_sha256: Binary SHA256 hash
            technique: Exploitation technique used
            payload: Exploit payload
            script: Generated exploit script
            success: Whether exploit succeeded
            crash_id: Optional crash ID this exploits
            notes: Additional notes

        Returns:
            Database row ID
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO exploits
                (binary_sha256, crash_id, technique, payload, script, success, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    binary_sha256,
                    crash_id,
                    technique,
                    payload,
                    script,
                    1 if success else 0,
                    notes,
                ),
            )
            return cursor.lastrowid

    def get_exploits(
        self,
        binary_sha256: str,
        successful_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve exploit attempts.

        Args:
            binary_sha256: Binary SHA256 hash
            successful_only: Only return successful exploits

        Returns:
            List of exploit dictionaries
        """
        with self._connection() as conn:
            if successful_only:
                rows = conn.execute(
                    """
                    SELECT * FROM exploits
                    WHERE binary_sha256 = ? AND success = 1
                    ORDER BY created_at DESC
                    """,
                    (binary_sha256,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM exploits
                    WHERE binary_sha256 = ?
                    ORDER BY created_at DESC
                    """,
                    (binary_sha256,),
                ).fetchall()

            return [
                {
                    "id": row["id"],
                    "technique": row["technique"],
                    "payload": row["payload"],
                    "script": row["script"],
                    "success": bool(row["success"]),
                    "notes": row["notes"],
                }
                for row in rows
            ]

    # Libc database methods
    def save_libc(
        self,
        libc_id: str,
        version: str,
        symbols: Dict[str, int],
        path: Optional[str] = None,
    ) -> int:
        """
        Save libc information.

        Args:
            libc_id: Libc database ID
            version: Libc version string
            symbols: Symbol to offset mapping
            path: Local file path

        Returns:
            Database row ID
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT OR REPLACE INTO libcs
                (libc_id, version, symbols, path)
                VALUES (?, ?, ?, ?)
                """,
                (libc_id, version, json.dumps(symbols), path),
            )
            return cursor.lastrowid

    def get_libc(self, libc_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached libc information.

        Args:
            libc_id: Libc database ID

        Returns:
            Libc data dict or None
        """
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM libcs WHERE libc_id = ?",
                (libc_id,),
            ).fetchone()

            if row:
                return {
                    "libc_id": row["libc_id"],
                    "version": row["version"],
                    "symbols": json.loads(row["symbols"]),
                    "path": row["path"],
                }
            return None

    def search_libc_by_symbols(
        self,
        symbols: Dict[str, int],
    ) -> List[Dict[str, Any]]:
        """
        Search for libc by known symbol offsets.

        Args:
            symbols: Known symbol name -> last 3 hex digits

        Returns:
            List of matching libc entries
        """
        # This is a simplified local search
        # In practice, you'd want to query libc.rip or similar
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM libcs").fetchall()

            matches = []
            for row in rows:
                cached_symbols = json.loads(row["symbols"])
                match = True
                for name, offset_suffix in symbols.items():
                    if name in cached_symbols:
                        if (cached_symbols[name] & 0xFFF) != offset_suffix:
                            match = False
                            break
                    else:
                        match = False
                        break

                if match:
                    matches.append({
                        "libc_id": row["libc_id"],
                        "version": row["version"],
                        "symbols": cached_symbols,
                        "path": row["path"],
                    })

            return matches

    # Utility methods
    def clear_cache(self, binary_sha256: Optional[str] = None) -> None:
        """
        Clear cached data.

        Args:
            binary_sha256: If provided, only clear data for this binary
        """
        with self._connection() as conn:
            if binary_sha256:
                conn.execute(
                    "DELETE FROM gadgets WHERE binary_sha256 = ?",
                    (binary_sha256,),
                )
                conn.execute(
                    "DELETE FROM crashes WHERE binary_sha256 = ?",
                    (binary_sha256,),
                )
                conn.execute(
                    "DELETE FROM exploits WHERE binary_sha256 = ?",
                    (binary_sha256,),
                )
                conn.execute(
                    "DELETE FROM symbols WHERE binary_sha256 = ?",
                    (binary_sha256,),
                )
                conn.execute(
                    "DELETE FROM binaries WHERE sha256 = ?",
                    (binary_sha256,),
                )
            else:
                conn.execute("DELETE FROM gadgets")
                conn.execute("DELETE FROM crashes")
                conn.execute("DELETE FROM exploits")
                conn.execute("DELETE FROM symbols")
                conn.execute("DELETE FROM binaries")

    def stats(self) -> Dict[str, int]:
        """Get database statistics."""
        with self._connection() as conn:
            stats = {}
            for table in ["binaries", "gadgets", "crashes", "exploits", "libcs"]:
                row = conn.execute(f"SELECT COUNT(*) as cnt FROM {table}").fetchone()
                stats[table] = row["cnt"]
            return stats
