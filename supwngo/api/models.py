"""
API data models using Pydantic.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime

try:
    from pydantic import BaseModel, Field
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    # Fallback to dataclasses
    BaseModel = object
    def Field(*args, **kwargs):
        return None


class JobState(str, Enum):
    """Job execution states."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VulnType(str, Enum):
    """Vulnerability types."""
    STACK_BOF = "stack_buffer_overflow"
    HEAP_BOF = "heap_buffer_overflow"
    FORMAT_STRING = "format_string"
    INTEGER_OVERFLOW = "integer_overflow"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    RACE_CONDITION = "race_condition"
    OTHER = "other"


class ProtectionInfo(BaseModel if PYDANTIC_AVAILABLE else object):
    """Binary protection information."""
    nx: bool = False
    pie: bool = False
    canary: bool = False
    relro: str = "None"
    aslr: bool = False
    fortify: bool = False

    if not PYDANTIC_AVAILABLE:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)


class VulnerabilityInfo(BaseModel if PYDANTIC_AVAILABLE else object):
    """Vulnerability information."""
    vuln_type: str
    severity: str = "medium"
    location: str = ""
    description: str = ""
    confidence: float = 0.0
    exploitable: bool = False

    if not PYDANTIC_AVAILABLE:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)


class GadgetInfo(BaseModel if PYDANTIC_AVAILABLE else object):
    """ROP gadget information."""
    address: int
    instructions: str
    type: str = ""

    if not PYDANTIC_AVAILABLE:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)


# Request Models
class AnalysisRequest(BaseModel if PYDANTIC_AVAILABLE else object):
    """Binary analysis request."""
    binary_path: Optional[str] = None
    binary_data: Optional[str] = None  # Base64 encoded
    analysis_types: List[str] = ["static", "protections", "vulns"]
    timeout: int = 300

    if not PYDANTIC_AVAILABLE:
        def __init__(self, **kwargs):
            self.binary_path = kwargs.get('binary_path')
            self.binary_data = kwargs.get('binary_data')
            self.analysis_types = kwargs.get('analysis_types', ["static", "protections", "vulns"])
            self.timeout = kwargs.get('timeout', 300)


class ExploitRequest(BaseModel if PYDANTIC_AVAILABLE else object):
    """Exploit generation request."""
    binary_path: Optional[str] = None
    binary_data: Optional[str] = None
    vuln_type: Optional[str] = None
    target_function: Optional[str] = None
    shellcode: Optional[str] = None  # Base64 encoded
    options: Dict[str, Any] = {}

    if not PYDANTIC_AVAILABLE:
        def __init__(self, **kwargs):
            self.binary_path = kwargs.get('binary_path')
            self.binary_data = kwargs.get('binary_data')
            self.vuln_type = kwargs.get('vuln_type')
            self.target_function = kwargs.get('target_function')
            self.shellcode = kwargs.get('shellcode')
            self.options = kwargs.get('options', {})


class ROPRequest(BaseModel if PYDANTIC_AVAILABLE else object):
    """ROP chain building request."""
    binary_path: Optional[str] = None
    binary_data: Optional[str] = None
    chain_type: str = "execve"  # execve, mprotect, custom
    target_function: Optional[str] = None
    arguments: List[int] = []
    bad_chars: str = ""  # Hex string of bad chars

    if not PYDANTIC_AVAILABLE:
        def __init__(self, **kwargs):
            self.binary_path = kwargs.get('binary_path')
            self.binary_data = kwargs.get('binary_data')
            self.chain_type = kwargs.get('chain_type', 'execve')
            self.target_function = kwargs.get('target_function')
            self.arguments = kwargs.get('arguments', [])
            self.bad_chars = kwargs.get('bad_chars', '')


class LibcRequest(BaseModel if PYDANTIC_AVAILABLE else object):
    """Libc identification request."""
    symbols: Dict[str, int]  # symbol_name -> leaked_address

    if not PYDANTIC_AVAILABLE:
        def __init__(self, **kwargs):
            self.symbols = kwargs.get('symbols', {})


# Response Models
class AnalysisResponse(BaseModel if PYDANTIC_AVAILABLE else object):
    """Binary analysis response."""
    success: bool
    binary_name: str = ""
    architecture: str = ""
    bits: int = 0
    protections: Optional[ProtectionInfo] = None
    vulnerabilities: List[VulnerabilityInfo] = []
    dangerous_functions: List[str] = []
    symbols_count: int = 0
    gadgets_count: int = 0
    analysis_time: float = 0.0
    error: Optional[str] = None

    if not PYDANTIC_AVAILABLE:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)


class ExploitResponse(BaseModel if PYDANTIC_AVAILABLE else object):
    """Exploit generation response."""
    success: bool
    exploit_type: str = ""
    payload: Optional[str] = None  # Base64 encoded
    payload_hex: Optional[str] = None
    script: Optional[str] = None  # Python exploit script
    notes: List[str] = []
    generation_time: float = 0.0
    error: Optional[str] = None

    if not PYDANTIC_AVAILABLE:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)


class ROPResponse(BaseModel if PYDANTIC_AVAILABLE else object):
    """ROP chain response."""
    success: bool
    chain: Optional[str] = None  # Base64 encoded
    chain_hex: Optional[str] = None
    gadgets_used: List[GadgetInfo] = []
    chain_length: int = 0
    notes: List[str] = []
    error: Optional[str] = None

    if not PYDANTIC_AVAILABLE:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)


class LibcResponse(BaseModel if PYDANTIC_AVAILABLE else object):
    """Libc identification response."""
    success: bool
    libc_id: Optional[str] = None
    libc_name: Optional[str] = None
    download_url: Optional[str] = None
    symbols: Dict[str, int] = {}
    buildid: Optional[str] = None
    error: Optional[str] = None

    if not PYDANTIC_AVAILABLE:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)


class JobStatus(BaseModel if PYDANTIC_AVAILABLE else object):
    """Async job status."""
    job_id: str
    state: str
    progress: float = 0.0
    message: str = ""
    created_at: str = ""
    updated_at: str = ""
    result: Optional[Dict[str, Any]] = None

    if not PYDANTIC_AVAILABLE:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)


class JobResult(BaseModel if PYDANTIC_AVAILABLE else object):
    """Completed job result."""
    job_id: str
    success: bool
    result_type: str
    data: Dict[str, Any] = {}
    error: Optional[str] = None
    completed_at: str = ""

    if not PYDANTIC_AVAILABLE:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)


class HealthResponse(BaseModel if PYDANTIC_AVAILABLE else object):
    """Health check response."""
    status: str = "healthy"
    version: str = ""
    uptime: float = 0.0
    jobs_processed: int = 0
    jobs_pending: int = 0

    if not PYDANTIC_AVAILABLE:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
