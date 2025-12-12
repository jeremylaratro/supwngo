"""
Configuration management for AutoPwn.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class FuzzingConfig:
    """Fuzzing campaign configuration."""
    timeout: int = 3600  # seconds
    cores: int = 4
    memory_limit: int = 1024  # MB
    use_qemu: bool = True
    use_asan: bool = False
    dictionary: Optional[str] = None


@dataclass
class SymbolicConfig:
    """Symbolic execution configuration."""
    timeout: int = 300  # seconds
    max_states: int = 10000
    auto_load_libs: bool = False
    use_sim_procedures: bool = True
    exploration_technique: str = "dfs"  # dfs, bfs, or explore


@dataclass
class ExploitConfig:
    """Exploit generation configuration."""
    bad_chars: List[int] = field(default_factory=lambda: [0x00, 0x0a, 0x0d])
    preferred_technique: str = "auto"  # auto, rop, shellcode, ret2libc
    max_rop_chain_length: int = 50
    shellcode_encoder: Optional[str] = None
    target_arch: str = "auto"


@dataclass
class Config:
    """
    Main configuration class for AutoPwn.

    Configuration can be loaded from:
    1. Default values
    2. Config file (~/.autopwn/config.json)
    3. Environment variables (AUTOPWN_*)
    4. Command line arguments
    """

    # General settings
    output_dir: str = "./autopwn_output"
    verbose: int = 1
    database_path: str = "~/.autopwn/autopwn.db"

    # Tool paths
    afl_path: str = "afl-fuzz"
    afl_tmin_path: str = "afl-tmin"
    honggfuzz_path: str = "honggfuzz"
    gdb_path: str = "gdb"

    # Libc database settings
    libc_database_url: str = "https://libc.rip/api"
    local_libc_dir: str = "~/.autopwn/libcs"

    # Sub-configurations
    fuzzing: FuzzingConfig = field(default_factory=FuzzingConfig)
    symbolic: SymbolicConfig = field(default_factory=SymbolicConfig)
    exploit: ExploitConfig = field(default_factory=ExploitConfig)

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "Config":
        """
        Load configuration from file and environment.

        Args:
            config_path: Optional path to config file

        Returns:
            Loaded Config instance
        """
        config = cls()

        # Load from default config file
        default_path = Path.home() / ".autopwn" / "config.json"
        if config_path:
            config_file = Path(config_path)
        elif default_path.exists():
            config_file = default_path
        else:
            config_file = None

        if config_file and config_file.exists():
            with open(config_file) as f:
                data = json.load(f)
                config = cls._from_dict(data)

        # Override with environment variables
        config._load_from_env()

        return config

    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> "Config":
        """Create Config from dictionary."""
        fuzzing_data = data.pop("fuzzing", {})
        symbolic_data = data.pop("symbolic", {})
        exploit_data = data.pop("exploit", {})

        return cls(
            fuzzing=FuzzingConfig(**fuzzing_data),
            symbolic=SymbolicConfig(**symbolic_data),
            exploit=ExploitConfig(**exploit_data),
            **data
        )

    def _load_from_env(self) -> None:
        """Load configuration from environment variables."""
        env_mapping = {
            "AUTOPWN_OUTPUT_DIR": "output_dir",
            "AUTOPWN_VERBOSE": ("verbose", int),
            "AUTOPWN_AFL_PATH": "afl_path",
            "AUTOPWN_HONGGFUZZ_PATH": "honggfuzz_path",
            "AUTOPWN_GDB_PATH": "gdb_path",
            "AUTOPWN_LIBC_DB_URL": "libc_database_url",
        }

        for env_var, attr in env_mapping.items():
            value = os.environ.get(env_var)
            if value:
                if isinstance(attr, tuple):
                    attr_name, converter = attr
                    setattr(self, attr_name, converter(value))
                else:
                    setattr(self, attr, value)

    def save(self, config_path: Optional[str] = None) -> None:
        """
        Save configuration to file.

        Args:
            config_path: Optional path for config file
        """
        if config_path:
            path = Path(config_path)
        else:
            path = Path.home() / ".autopwn" / "config.json"

        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return asdict(self)

    def expand_paths(self) -> None:
        """Expand ~ in all path configurations."""
        self.output_dir = os.path.expanduser(self.output_dir)
        self.database_path = os.path.expanduser(self.database_path)
        self.local_libc_dir = os.path.expanduser(self.local_libc_dir)


# Global configuration instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = Config.load()
    return _config


def set_config(config: Config) -> None:
    """Set the global configuration instance."""
    global _config
    _config = config
