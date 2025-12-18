"""
Libc identification and offset lookup.
"""

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class LibcMatch:
    """A matching libc from database."""
    id: str
    version: str
    download_url: str = ""
    symbols: Dict[str, int] = field(default_factory=dict)
    buildid: str = ""


class LibcDatabase:
    """
    Libc identification and offset lookup.

    Sources:
    - libc.rip (primary)
    - libc.blukat.me (fallback)
    - Local database
    """

    # API endpoints
    LIBC_RIP_API = "https://libc.rip/api"
    LIBC_BLUKAT_API = "https://libc.blukat.me/api"

    def __init__(self, cache_dir: Optional[str] = None):
        """
        Initialize libc database.

        Args:
            cache_dir: Directory for cached libcs
        """
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / ".supwngo" / "libcs"

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._local_db: Dict[str, LibcMatch] = {}

    def identify(
        self,
        known_symbols: Dict[str, int],
    ) -> List[LibcMatch]:
        """
        Identify libc from known symbol offsets.

        Args:
            known_symbols: Symbol name -> last 3 hex digits of address

        Returns:
            List of matching libc entries
        """
        matches = []

        # Normalize symbols (extract last 3 hex digits)
        normalized = {}
        for name, addr in known_symbols.items():
            normalized[name] = addr & 0xFFF

        # Try libc.rip first
        try:
            matches = self._query_libc_rip(normalized)
            if matches:
                return matches
        except Exception as e:
            logger.debug(f"libc.rip query failed: {e}")

        # Try libc.blukat.me
        try:
            matches = self._query_blukat(normalized)
            if matches:
                return matches
        except Exception as e:
            logger.debug(f"blukat query failed: {e}")

        # Search local database
        matches = self._search_local(normalized)

        return matches

    def _query_libc_rip(
        self,
        symbols: Dict[str, int],
    ) -> List[LibcMatch]:
        """Query libc.rip API."""
        matches = []

        # Build query
        query = {"symbols": symbols}

        response = requests.post(
            f"{self.LIBC_RIP_API}/find",
            json=query,
            timeout=30,
        )

        if response.status_code == 200:
            data = response.json()

            for entry in data:
                match = LibcMatch(
                    id=entry.get("id", ""),
                    version=entry.get("id", ""),
                    download_url=entry.get("download_url", ""),
                    symbols=entry.get("symbols", {}),
                    buildid=entry.get("buildid", ""),
                )
                matches.append(match)

        return matches

    def _query_blukat(
        self,
        symbols: Dict[str, int],
    ) -> List[LibcMatch]:
        """Query libc.blukat.me API."""
        matches = []

        # Build query string
        params = []
        for name, offset in symbols.items():
            params.append(f"{name}={offset:03x}")

        query_str = "&".join(params)
        url = f"{self.LIBC_BLUKAT_API}?{query_str}"

        response = requests.get(url, timeout=30)

        if response.status_code == 200:
            # Parse response (HTML or JSON depending on endpoint)
            # This is simplified - actual parsing depends on API format
            pass

        return matches

    def _search_local(
        self,
        symbols: Dict[str, int],
    ) -> List[LibcMatch]:
        """Search local libc database."""
        matches = []

        for libc_id, libc in self._local_db.items():
            match = True
            for name, offset in symbols.items():
                if name in libc.symbols:
                    if (libc.symbols[name] & 0xFFF) != offset:
                        match = False
                        break
                else:
                    match = False
                    break

            if match:
                matches.append(libc)

        return matches

    def get_offset(
        self,
        libc_id: str,
        symbol: str,
    ) -> Optional[int]:
        """
        Get symbol offset for specific libc.

        Args:
            libc_id: Libc identifier
            symbol: Symbol name

        Returns:
            Offset or None
        """
        # Check local cache
        if libc_id in self._local_db:
            return self._local_db[libc_id].symbols.get(symbol)

        # Query API
        try:
            response = requests.get(
                f"{self.LIBC_RIP_API}/libc/{libc_id}",
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("symbols", {}).get(symbol)

        except Exception as e:
            logger.error(f"Failed to get offset: {e}")

        return None

    def get_all_symbols(
        self,
        libc_id: str,
    ) -> Dict[str, int]:
        """
        Get all symbols for a libc.

        Args:
            libc_id: Libc identifier

        Returns:
            Symbol -> offset mapping
        """
        # Check cache
        if libc_id in self._local_db:
            return self._local_db[libc_id].symbols

        # Query API
        try:
            response = requests.get(
                f"{self.LIBC_RIP_API}/libc/{libc_id}",
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("symbols", {})

        except Exception as e:
            logger.error(f"Failed to get symbols: {e}")

        return {}

    def download_libc(
        self,
        libc_id: str,
        download_url: Optional[str] = None,
    ) -> Optional[Path]:
        """
        Download libc to cache.

        Args:
            libc_id: Libc identifier
            download_url: Direct download URL

        Returns:
            Path to downloaded libc or None
        """
        # Check if already cached
        cache_path = self.cache_dir / f"{libc_id}.so"
        if cache_path.exists():
            return cache_path

        # Get download URL if not provided
        if not download_url:
            try:
                response = requests.get(
                    f"{self.LIBC_RIP_API}/libc/{libc_id}",
                    timeout=30,
                )
                if response.status_code == 200:
                    download_url = response.json().get("download_url")
            except Exception:
                pass

        if not download_url:
            logger.error(f"No download URL for {libc_id}")
            return None

        # Download
        try:
            logger.info(f"Downloading libc {libc_id}...")
            response = requests.get(download_url, timeout=120)

            if response.status_code == 200:
                cache_path.write_bytes(response.content)
                logger.info(f"Saved to {cache_path}")
                return cache_path

        except Exception as e:
            logger.error(f"Download failed: {e}")

        return None

    def add_local_libc(
        self,
        libc_path: str,
    ) -> Optional[str]:
        """
        Add local libc to database.

        Args:
            libc_path: Path to libc file

        Returns:
            Libc ID or None
        """
        path = Path(libc_path)
        if not path.exists():
            return None

        try:
            from pwn import ELF

            libc = ELF(str(path))

            # Generate ID from hash
            data = path.read_bytes()
            libc_id = hashlib.sha256(data).hexdigest()[:16]

            # Extract symbols
            symbols = {}
            for name in ["system", "execve", "puts", "printf", "__libc_start_main"]:
                if name in libc.symbols:
                    symbols[name] = libc.symbols[name]

            # Find /bin/sh
            binsh = list(libc.search(b"/bin/sh\x00"))
            if binsh:
                symbols["str_bin_sh"] = binsh[0]

            match = LibcMatch(
                id=libc_id,
                version=path.name,
                symbols=symbols,
            )

            self._local_db[libc_id] = match

            # Copy to cache
            cache_path = self.cache_dir / f"{libc_id}.so"
            if not cache_path.exists():
                import shutil
                shutil.copy(path, cache_path)

            return libc_id

        except Exception as e:
            logger.error(f"Failed to add libc: {e}")
            return None

    def identify_from_leaks(
        self,
        puts: Optional[int] = None,
        printf: Optional[int] = None,
        system: Optional[int] = None,
        __libc_start_main: Optional[int] = None,
    ) -> List[LibcMatch]:
        """
        Identify libc from leaked addresses.

        Args:
            Various leaked function addresses

        Returns:
            Matching libcs
        """
        symbols = {}

        if puts:
            symbols["puts"] = puts
        if printf:
            symbols["printf"] = printf
        if system:
            symbols["system"] = system
        if __libc_start_main:
            symbols["__libc_start_main"] = __libc_start_main

        if not symbols:
            return []

        return self.identify(symbols)

    def calculate_base(
        self,
        libc_match: LibcMatch,
        leaked_symbol: str,
        leaked_addr: int,
    ) -> int:
        """
        Calculate libc base from leak.

        Args:
            libc_match: Matched libc
            leaked_symbol: Symbol that was leaked
            leaked_addr: Leaked address

        Returns:
            Libc base address
        """
        offset = libc_match.symbols.get(leaked_symbol, 0)
        return leaked_addr - offset

    def get_one_gadgets(
        self,
        libc_path: Optional[str] = None,
        libc_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Find one_gadget RCE addresses in libc.

        Args:
            libc_path: Path to libc file
            libc_id: Or libc ID to download/use from cache

        Returns:
            List of one_gadget dicts with offset and constraints
        """
        import subprocess

        # Get libc path
        if not libc_path and libc_id:
            cached = self.cache_dir / f"{libc_id}.so"
            if cached.exists():
                libc_path = str(cached)
            else:
                downloaded = self.download_libc(libc_id)
                if downloaded:
                    libc_path = str(downloaded)

        if not libc_path:
            return []

        gadgets = []

        try:
            result = subprocess.run(
                ["one_gadget", libc_path, "-r"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode == 0:
                # Parse one_gadget output
                # Format: offset constraints
                current_gadget = {}

                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if not line:
                        if current_gadget:
                            gadgets.append(current_gadget)
                            current_gadget = {}
                        continue

                    if line.startswith("0x"):
                        # New gadget
                        if current_gadget:
                            gadgets.append(current_gadget)
                        parts = line.split()
                        current_gadget = {
                            "offset": int(parts[0], 16),
                            "constraints": [],
                        }
                    elif current_gadget and "==" in line or "NULL" in line:
                        current_gadget["constraints"].append(line)

                if current_gadget:
                    gadgets.append(current_gadget)

        except FileNotFoundError:
            logger.warning("one_gadget tool not found, install with: gem install one_gadget")
        except subprocess.TimeoutExpired:
            logger.warning("one_gadget timed out")
        except Exception as e:
            logger.debug(f"one_gadget failed: {e}")

        return gadgets

    def get_useful_offsets(
        self,
        libc_id: str,
    ) -> Dict[str, int]:
        """
        Get commonly useful offsets for exploitation.

        Args:
            libc_id: Libc identifier

        Returns:
            Dict of useful symbol offsets
        """
        useful_symbols = [
            # Execution
            "system",
            "execve",
            "execvp",
            "popen",

            # Memory
            "mprotect",
            "mmap",

            # Hooks (glibc < 2.34)
            "__malloc_hook",
            "__free_hook",
            "__realloc_hook",

            # Leak targets
            "puts",
            "printf",
            "write",
            "__libc_start_main",

            # Strings
            "str_bin_sh",

            # FILE structures
            "_IO_2_1_stdin_",
            "_IO_2_1_stdout_",
            "_IO_2_1_stderr_",
            "_IO_list_all",

            # Vtables
            "_IO_file_jumps",

            # Stack
            "environ",
            "__environ",
        ]

        all_syms = self.get_all_symbols(libc_id)

        result = {}
        for sym in useful_symbols:
            if sym in all_syms:
                result[sym] = all_syms[sym]

        # Try to find /bin/sh string
        libc_path = self.cache_dir / f"{libc_id}.so"
        if libc_path.exists():
            try:
                from pwn import ELF
                libc = ELF(str(libc_path), checksec=False)
                binsh = list(libc.search(b"/bin/sh\x00"))
                if binsh:
                    result["str_bin_sh"] = binsh[0]
            except Exception:
                pass

        return result

    def detect_version(
        self,
        libc_path: str,
    ) -> Optional[str]:
        """
        Detect glibc version from binary.

        Args:
            libc_path: Path to libc

        Returns:
            Version string like "2.31"
        """
        import subprocess

        try:
            # Method 1: strings | grep GLIBC
            result = subprocess.run(
                ["strings", libc_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            for line in result.stdout.split("\n"):
                # Match patterns like "GLIBC_2.31" or "GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.2)"
                import re
                match = re.search(r'GLIBC[_ ](\d+\.\d+)', line)
                if match:
                    return match.group(1)

                match = re.search(r'release version (\d+\.\d+)', line)
                if match:
                    return match.group(1)

        except Exception as e:
            logger.debug(f"Version detection failed: {e}")

        return None

    def find_libc_in_process(
        self,
        pid: int,
    ) -> Optional[Tuple[str, int]]:
        """
        Find libc path and base address from running process.

        Args:
            pid: Process ID

        Returns:
            Tuple of (libc_path, base_address) or None
        """
        try:
            maps_path = f"/proc/{pid}/maps"

            with open(maps_path) as f:
                for line in f:
                    if "libc" in line and ".so" in line:
                        parts = line.split()
                        addr_range = parts[0]
                        path = parts[-1]

                        base = int(addr_range.split("-")[0], 16)
                        return (path, base)

        except Exception as e:
            logger.debug(f"Failed to find libc in process: {e}")

        return None

    def summary(self) -> str:
        """Get database summary."""
        return f"""
Libc Database
=============
Cache dir: {self.cache_dir}
Local entries: {len(self._local_db)}
Cached libcs: {len(list(self.cache_dir.glob('*.so')))}

APIs:
- libc.rip: {self.LIBC_RIP_API}
- libc.blukat: {self.LIBC_BLUKAT_API}

Usage:
  db = LibcDatabase()
  matches = db.identify({{"puts": 0x123, "printf": 0x456}})
  offsets = db.get_useful_offsets(matches[0].id)
  gadgets = db.get_one_gadgets(libc_id=matches[0].id)
"""
