"""
Firmware analysis and extraction.

Provides firmware extraction and analysis using binwalk and custom parsers.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import subprocess
import tempfile
import shutil

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class FilesystemType(Enum):
    """Common embedded filesystem types."""
    SQUASHFS = auto()
    JFFS2 = auto()
    CRAMFS = auto()
    ROMFS = auto()
    UBIFS = auto()
    EXT2 = auto()
    EXT4 = auto()
    YAFFS = auto()
    UNKNOWN = auto()


class CompressionType(Enum):
    """Compression types in firmware."""
    NONE = auto()
    GZIP = auto()
    LZMA = auto()
    XZ = auto()
    LZO = auto()
    ZSTD = auto()
    BZIP2 = auto()


@dataclass
class ExtractedFile:
    """Information about an extracted file."""
    path: Path
    original_offset: int
    size: int
    file_type: str
    is_executable: bool = False
    architecture: str = ""


@dataclass
class FilesystemInfo:
    """Information about extracted filesystem."""
    fs_type: FilesystemType
    root_path: Path
    total_files: int = 0
    executables: List[Path] = field(default_factory=list)
    config_files: List[Path] = field(default_factory=list)
    web_files: List[Path] = field(default_factory=list)


@dataclass
class FirmwareInfo:
    """Complete firmware analysis results."""
    path: Path
    size: int
    architecture: str = ""
    endianness: str = ""  # "little" or "big"

    # Extracted components
    filesystems: List[FilesystemInfo] = field(default_factory=list)
    kernels: List[ExtractedFile] = field(default_factory=list)
    bootloaders: List[ExtractedFile] = field(default_factory=list)

    # Security
    has_hardcoded_credentials: bool = False
    hardcoded_credentials: List[Tuple[str, str]] = field(default_factory=list)
    private_keys: List[Path] = field(default_factory=list)

    # Vulnerabilities
    dangerous_binaries: List[Path] = field(default_factory=list)


class FirmwareAnalyzer:
    """
    Analyze and extract firmware images.

    Uses binwalk for extraction and provides additional analysis.

    Example:
        fw = FirmwareAnalyzer("firmware.bin")

        # Extract firmware
        fw.extract()

        # Get analysis results
        info = fw.analyze()

        # Find specific files
        binaries = fw.find_binaries(arch="arm")
        configs = fw.find_config_files()
    """

    # Common interesting files
    INTERESTING_CONFIGS = [
        "passwd", "shadow", "httpd.conf", "nginx.conf",
        "sshd_config", "dropbear", "config.xml", "settings.conf",
        "database.db", "credentials", "secrets",
    ]

    INTERESTING_EXTENSIONS = [
        ".pem", ".key", ".crt", ".p12", ".pfx",  # Certificates
        ".conf", ".cfg", ".ini", ".xml", ".json",  # Configs
        ".sh", ".py", ".pl",  # Scripts
        ".so", ".ko",  # Libraries/modules
    ]

    def __init__(self, path: Union[str, Path], extract_dir: Optional[Path] = None):
        """
        Initialize firmware analyzer.

        Args:
            path: Path to firmware image
            extract_dir: Directory for extraction (temp if not specified)
        """
        self.path = Path(path)
        self.extract_dir = extract_dir or Path(tempfile.mkdtemp(prefix="supwngo_fw_"))

        if not self.path.exists():
            raise FileNotFoundError(f"Firmware not found: {path}")

        self.info = FirmwareInfo(
            path=self.path,
            size=self.path.stat().st_size
        )

        self._extracted = False

    def extract(self, use_binwalk: bool = True) -> bool:
        """
        Extract firmware contents.

        Args:
            use_binwalk: Use binwalk for extraction

        Returns:
            True if extraction successful
        """
        if use_binwalk:
            return self._extract_binwalk()
        else:
            return self._extract_manual()

    def _extract_binwalk(self) -> bool:
        """Extract using binwalk."""
        try:
            # Check if binwalk is available
            result = subprocess.run(
                ["which", "binwalk"],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                logger.warning("binwalk not found, trying manual extraction")
                return self._extract_manual()

            # Run binwalk extraction
            extract_path = self.extract_dir / "extracted"
            extract_path.mkdir(parents=True, exist_ok=True)

            result = subprocess.run(
                ["binwalk", "-e", "-C", str(extract_path), str(self.path)],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode == 0:
                self._extracted = True
                logger.info(f"Firmware extracted to {extract_path}")
                return True
            else:
                logger.warning(f"binwalk extraction failed: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("Firmware extraction timed out")
            return False
        except Exception as e:
            logger.error(f"Extraction error: {e}")
            return False

    def _extract_manual(self) -> bool:
        """Manual extraction without binwalk."""
        # Basic extraction - look for common signatures
        try:
            with open(self.path, 'rb') as f:
                data = f.read()

            # Look for squashfs
            sqsh_offset = data.find(b'hsqs')  # Little-endian squashfs
            if sqsh_offset == -1:
                sqsh_offset = data.find(b'sqsh')  # Big-endian

            if sqsh_offset != -1:
                # Extract squashfs portion
                sqsh_path = self.extract_dir / "squashfs.img"
                with open(sqsh_path, 'wb') as f:
                    f.write(data[sqsh_offset:])
                logger.info(f"Found squashfs at offset {sqsh_offset}")

            # Look for gzip compressed data
            gzip_offset = data.find(b'\x1f\x8b\x08')
            if gzip_offset != -1:
                gzip_path = self.extract_dir / "compressed.gz"
                with open(gzip_path, 'wb') as f:
                    f.write(data[gzip_offset:])
                logger.info(f"Found gzip data at offset {gzip_offset}")

            self._extracted = True
            return True

        except Exception as e:
            logger.error(f"Manual extraction failed: {e}")
            return False

    def analyze(self) -> FirmwareInfo:
        """
        Perform comprehensive firmware analysis.

        Returns:
            FirmwareInfo with analysis results
        """
        if not self._extracted:
            self.extract()

        # Detect architecture from binaries
        self._detect_architecture()

        # Find filesystems
        self._analyze_filesystems()

        # Find interesting files
        self._find_interesting_files()

        # Check for security issues
        self._check_security()

        return self.info

    def _detect_architecture(self):
        """Detect firmware architecture from binaries."""
        # Find ELF files
        for binary in self.find_binaries():
            try:
                with open(binary, 'rb') as f:
                    magic = f.read(20)

                if magic[:4] == b'\x7fELF':
                    # ELF file
                    ei_data = magic[5]
                    self.info.endianness = "little" if ei_data == 1 else "big"

                    e_machine = int.from_bytes(magic[18:20],
                                              'little' if ei_data == 1 else 'big')

                    if e_machine == 40:  # EM_ARM
                        self.info.architecture = "arm"
                    elif e_machine == 8:  # EM_MIPS
                        self.info.architecture = "mips"
                    elif e_machine == 183:  # EM_AARCH64
                        self.info.architecture = "arm64"
                    elif e_machine == 3:  # EM_386
                        self.info.architecture = "x86"
                    elif e_machine == 62:  # EM_X86_64
                        self.info.architecture = "x86_64"

                    if self.info.architecture:
                        logger.info(f"Detected architecture: {self.info.architecture}")
                        break

            except Exception:
                continue

    def _analyze_filesystems(self):
        """Analyze extracted filesystems."""
        extract_path = self.extract_dir / "extracted"

        if not extract_path.exists():
            extract_path = self.extract_dir

        # Walk extraction directory
        for item in extract_path.rglob("*"):
            if item.is_dir():
                # Check if this looks like a filesystem root
                if (item / "bin").exists() or (item / "etc").exists():
                    fs_info = FilesystemInfo(
                        fs_type=FilesystemType.UNKNOWN,
                        root_path=item
                    )

                    # Count files and find executables
                    for f in item.rglob("*"):
                        if f.is_file():
                            fs_info.total_files += 1

                            # Check if executable
                            try:
                                with open(f, 'rb') as fp:
                                    magic = fp.read(4)
                                if magic == b'\x7fELF':
                                    fs_info.executables.append(f)
                            except Exception:
                                pass

                    self.info.filesystems.append(fs_info)

    def _find_interesting_files(self):
        """Find interesting files in extracted firmware."""
        for fs in self.info.filesystems:
            for f in fs.root_path.rglob("*"):
                if not f.is_file():
                    continue

                name = f.name.lower()

                # Config files
                if any(cfg in name for cfg in self.INTERESTING_CONFIGS):
                    fs.config_files.append(f)

                # Web files
                if f.suffix in ['.html', '.php', '.cgi', '.asp', '.js']:
                    fs.web_files.append(f)

                # Keys/certs
                if f.suffix in ['.pem', '.key', '.crt']:
                    self.info.private_keys.append(f)

    def _check_security(self):
        """Check for security issues."""
        # Check for hardcoded credentials in common locations
        credential_patterns = [
            b'password',
            b'passwd',
            b'admin:',
            b'root:',
            b'secret',
            b'apikey',
            b'api_key',
        ]

        for fs in self.info.filesystems:
            # Check passwd file
            passwd_path = fs.root_path / "etc" / "passwd"
            if passwd_path.exists():
                try:
                    content = passwd_path.read_text()
                    for line in content.splitlines():
                        parts = line.split(':')
                        if len(parts) >= 2 and parts[1] not in ['x', '*', '!']:
                            self.info.has_hardcoded_credentials = True
                            self.info.hardcoded_credentials.append((parts[0], "passwd hash"))
                except Exception:
                    pass

            # Check shadow file
            shadow_path = fs.root_path / "etc" / "shadow"
            if shadow_path.exists():
                try:
                    content = shadow_path.read_text()
                    for line in content.splitlines():
                        parts = line.split(':')
                        if len(parts) >= 2 and parts[1] and parts[1] not in ['*', '!', '!!']:
                            self.info.has_hardcoded_credentials = True
                            self.info.hardcoded_credentials.append((parts[0], "shadow hash"))
                except Exception:
                    pass

    def find_binaries(self, arch: Optional[str] = None) -> List[Path]:
        """
        Find binary executables in extracted firmware.

        Args:
            arch: Filter by architecture ("arm", "mips", etc.)

        Returns:
            List of binary paths
        """
        binaries = []

        for fs in self.info.filesystems:
            binaries.extend(fs.executables)

        # If no filesystems analyzed, search manually
        if not binaries:
            for f in self.extract_dir.rglob("*"):
                if not f.is_file():
                    continue

                try:
                    with open(f, 'rb') as fp:
                        magic = fp.read(20)

                    if magic[:4] == b'\x7fELF':
                        if arch:
                            ei_data = magic[5]
                            e_machine = int.from_bytes(magic[18:20],
                                                      'little' if ei_data == 1 else 'big')

                            arch_map = {
                                "arm": 40,
                                "mips": 8,
                                "arm64": 183,
                                "x86": 3,
                                "x86_64": 62,
                            }

                            if arch_map.get(arch) != e_machine:
                                continue

                        binaries.append(f)
                except Exception:
                    continue

        return binaries

    def find_config_files(self) -> List[Path]:
        """Find configuration files."""
        configs = []
        for fs in self.info.filesystems:
            configs.extend(fs.config_files)
        return configs

    def find_web_files(self) -> List[Path]:
        """Find web-related files (potential vulnerabilities)."""
        web_files = []
        for fs in self.info.filesystems:
            web_files.extend(fs.web_files)
        return web_files

    def cleanup(self):
        """Remove extracted files."""
        if self.extract_dir.exists():
            shutil.rmtree(self.extract_dir)

    def summary(self) -> str:
        """Get firmware analysis summary."""
        lines = [
            "Firmware Analysis Summary",
            "=" * 40,
            f"File: {self.path.name}",
            f"Size: {self.info.size:,} bytes",
            f"Architecture: {self.info.architecture or 'Unknown'}",
            f"Endianness: {self.info.endianness or 'Unknown'}",
            "",
            f"Filesystems: {len(self.info.filesystems)}",
        ]

        total_executables = sum(len(fs.executables) for fs in self.info.filesystems)
        lines.append(f"Executables: {total_executables}")

        if self.info.has_hardcoded_credentials:
            lines.append("")
            lines.append("SECURITY ISSUES:")
            lines.append(f"  Hardcoded credentials: {len(self.info.hardcoded_credentials)}")
            for user, loc in self.info.hardcoded_credentials[:5]:
                lines.append(f"    - {user} ({loc})")

        if self.info.private_keys:
            lines.append(f"  Private keys found: {len(self.info.private_keys)}")

        return "\n".join(lines)
