"""
Container escape detection and exploitation module.

Provides tools for:
- Detecting container environments
- Identifying escape vectors
- Exploiting container misconfigurations
- Privilege escalation from containers
"""

from supwngo.containers.detection import (
    ContainerDetector,
    ContainerType,
    ContainerInfo,
    detect_container,
)
from supwngo.containers.escapes import (
    ContainerEscape,
    EscapeVector,
    EscapeResult,
    DockerSocketEscape,
    PrivilegedContainerEscape,
    HostPathEscape,
    SysPtraceEscape,
    CgroupEscape,
    RuncEscape,
    DirtyPipeContainerEscape,
    find_escape_vectors,
    exploit_escape,
)

__all__ = [
    # Detection
    "ContainerDetector",
    "ContainerType",
    "ContainerInfo",
    "detect_container",
    # Escapes
    "ContainerEscape",
    "EscapeVector",
    "EscapeResult",
    "DockerSocketEscape",
    "PrivilegedContainerEscape",
    "HostPathEscape",
    "SysPtraceEscape",
    "CgroupEscape",
    "RuncEscape",
    "DirtyPipeContainerEscape",
    "find_escape_vectors",
    "exploit_escape",
]
