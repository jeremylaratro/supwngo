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

from autopwn.utils.logging import get_logger

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
            self.cache_dir = Path.home() / ".autopwn" / "libcs"

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

    def summary(self) -> str:
        """Get database summary."""
        return f"""
Libc Database
=============
Cache dir: {self.cache_dir}
Local entries: {len(self._local_db)}
Cached libcs: {len(list(self.cache_dir.glob('*.so')))}
"""
