"""
Container environment detection.

Detects various container runtimes and their configurations,
identifying potential security weaknesses.
"""

import os
import re
import socket
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class ContainerType(Enum):
    """Types of container environments."""
    NONE = auto()           # Not in a container
    DOCKER = auto()         # Docker container
    PODMAN = auto()         # Podman container
    LXC = auto()            # LXC container
    LXD = auto()            # LXD container
    KUBERNETES = auto()     # Kubernetes pod
    CONTAINERD = auto()     # containerd managed
    CRIO = auto()           # CRI-O managed
    RUNC = auto()           # Direct runc
    KATA = auto()           # Kata Containers (VM-based)
    GVISOR = auto()         # gVisor (sandboxed)
    FIREJAIL = auto()       # Firejail sandbox
    SYSTEMD_NSPAWN = auto() # systemd-nspawn
    WSL = auto()            # Windows Subsystem for Linux
    UNKNOWN = auto()        # Unknown container type


@dataclass
class ContainerInfo:
    """Detailed container environment information."""
    container_type: ContainerType
    container_id: str = ""
    hostname: str = ""
    image: str = ""
    runtime: str = ""
    privileged: bool = False
    capabilities: List[str] = field(default_factory=list)
    security_opts: List[str] = field(default_factory=list)
    namespaces: Dict[str, bool] = field(default_factory=dict)
    cgroups_version: int = 1
    seccomp_enabled: bool = True
    apparmor_profile: str = ""
    selinux_label: str = ""
    host_paths: List[str] = field(default_factory=list)
    devices: List[str] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)
    escape_potential: str = "low"


class ContainerDetector:
    """
    Detect container environments and security configuration.
    """

    # Container indicator files
    DOCKER_FILES = [
        "/.dockerenv",
        "/.dockerinit",
    ]

    CGROUP_PATTERNS = {
        ContainerType.DOCKER: [r"docker", r"containerd"],
        ContainerType.PODMAN: [r"libpod"],
        ContainerType.LXC: [r"lxc"],
        ContainerType.KUBERNETES: [r"kubepods", r"k8s"],
        ContainerType.CRIO: [r"crio"],
    }

    # Kubernetes environment indicators
    K8S_ENV_VARS = [
        "KUBERNETES_SERVICE_HOST",
        "KUBERNETES_PORT",
        "KUBERNETES_SERVICE_PORT",
    ]

    def __init__(self):
        self.info = ContainerInfo(container_type=ContainerType.NONE)

    def detect(self) -> ContainerInfo:
        """
        Detect container environment.

        Returns:
            ContainerInfo with detected settings
        """
        # Reset info
        self.info = ContainerInfo(container_type=ContainerType.NONE)
        self.info.hostname = socket.gethostname()

        # Check various indicators
        self._check_dockerenv()
        self._check_cgroup()
        self._check_kubernetes()
        self._check_init_system()
        self._check_proc_1()
        self._check_capabilities()
        self._check_namespaces()
        self._check_security()
        self._check_mounts()
        self._check_devices()

        # Assess escape potential
        self._assess_escape_potential()

        return self.info

    def _check_dockerenv(self):
        """Check for Docker indicator files."""
        for f in self.DOCKER_FILES:
            if os.path.exists(f):
                self.info.container_type = ContainerType.DOCKER
                logger.debug(f"Found Docker indicator: {f}")
                break

    def _check_cgroup(self):
        """Check cgroup for container runtime."""
        try:
            with open("/proc/1/cgroup", "r") as f:
                cgroup_content = f.read()

            # Check cgroup version
            if os.path.exists("/sys/fs/cgroup/cgroup.controllers"):
                self.info.cgroups_version = 2
            else:
                self.info.cgroups_version = 1

            # Match container patterns
            for ctype, patterns in self.CGROUP_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, cgroup_content, re.I):
                        self.info.container_type = ctype

                        # Try to extract container ID
                        match = re.search(r"docker/([a-f0-9]{64})", cgroup_content)
                        if match:
                            self.info.container_id = match.group(1)[:12]
                        break

        except (FileNotFoundError, PermissionError):
            pass

    def _check_kubernetes(self):
        """Check for Kubernetes environment."""
        for var in self.K8S_ENV_VARS:
            if var in os.environ:
                self.info.container_type = ContainerType.KUBERNETES
                break

        # Check for service account token
        sa_token = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        if os.path.exists(sa_token):
            self.info.container_type = ContainerType.KUBERNETES
            self.info.host_paths.append(sa_token)

    def _check_init_system(self):
        """Check init system for container indicators."""
        try:
            with open("/proc/1/comm", "r") as f:
                init = f.read().strip()

            if init in ("tini", "dumb-init"):
                # Common container init systems
                if self.info.container_type == ContainerType.NONE:
                    self.info.container_type = ContainerType.DOCKER

            elif init == "systemd-nspawn":
                self.info.container_type = ContainerType.SYSTEMD_NSPAWN

        except (FileNotFoundError, PermissionError):
            pass

    def _check_proc_1(self):
        """Check /proc/1 for container indicators."""
        try:
            # Check environment
            with open("/proc/1/environ", "rb") as f:
                env_data = f.read().decode("utf-8", errors="ignore")
                env_vars = dict(
                    item.split("=", 1) for item in env_data.split("\x00")
                    if "=" in item
                )
                self.info.environment = env_vars

                if "container" in env_vars:
                    container_val = env_vars["container"]
                    if container_val == "lxc":
                        self.info.container_type = ContainerType.LXC
                    elif container_val == "podman":
                        self.info.container_type = ContainerType.PODMAN

        except (FileNotFoundError, PermissionError):
            pass

    def _check_capabilities(self):
        """Check current capabilities."""
        try:
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("CapEff:"):
                        cap_hex = line.split(":")[1].strip()
                        cap_int = int(cap_hex, 16)

                        # Check for privileged indicators
                        CAP_SYS_ADMIN = 21
                        CAP_SYS_PTRACE = 19
                        CAP_NET_RAW = 13
                        CAP_NET_ADMIN = 12
                        CAP_DAC_OVERRIDE = 1
                        CAP_SYS_MODULE = 16

                        if cap_int & (1 << CAP_SYS_ADMIN):
                            self.info.capabilities.append("CAP_SYS_ADMIN")
                            self.info.privileged = True
                        if cap_int & (1 << CAP_SYS_PTRACE):
                            self.info.capabilities.append("CAP_SYS_PTRACE")
                        if cap_int & (1 << CAP_NET_RAW):
                            self.info.capabilities.append("CAP_NET_RAW")
                        if cap_int & (1 << CAP_NET_ADMIN):
                            self.info.capabilities.append("CAP_NET_ADMIN")
                        if cap_int & (1 << CAP_DAC_OVERRIDE):
                            self.info.capabilities.append("CAP_DAC_OVERRIDE")
                        if cap_int & (1 << CAP_SYS_MODULE):
                            self.info.capabilities.append("CAP_SYS_MODULE")

                        # Full capabilities = privileged
                        if cap_int == 0x3fffffffff:
                            self.info.privileged = True

        except (FileNotFoundError, PermissionError):
            pass

    def _check_namespaces(self):
        """Check namespace isolation."""
        ns_path = Path("/proc/self/ns")
        host_ns_path = Path("/proc/1/ns")

        namespaces = ["mnt", "pid", "net", "ipc", "uts", "user", "cgroup"]

        for ns in namespaces:
            try:
                container_ns = (ns_path / ns).resolve()
                host_ns = (host_ns_path / ns).resolve()

                # If same inode, we share namespace with host
                self.info.namespaces[ns] = container_ns != host_ns
            except (FileNotFoundError, PermissionError, OSError):
                self.info.namespaces[ns] = True  # Assume isolated

    def _check_security(self):
        """Check security mechanisms."""
        # Seccomp
        try:
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("Seccomp:"):
                        mode = int(line.split(":")[1].strip())
                        self.info.seccomp_enabled = mode > 0
        except (FileNotFoundError, PermissionError):
            pass

        # AppArmor
        try:
            with open("/proc/self/attr/current", "r") as f:
                profile = f.read().strip()
                self.info.apparmor_profile = profile
        except (FileNotFoundError, PermissionError):
            pass

        # SELinux
        try:
            with open("/proc/self/attr/current", "r") as f:
                label = f.read().strip()
                if ":" in label and not label.startswith("unconfined"):
                    self.info.selinux_label = label
        except (FileNotFoundError, PermissionError):
            pass

    def _check_mounts(self):
        """Check for sensitive host mounts."""
        sensitive_paths = [
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/var/run/containerd/containerd.sock",
            "/run/containerd/containerd.sock",
            "/var/run/crio/crio.sock",
            "/etc/kubernetes",
            "/var/lib/kubelet",
            "/etc/shadow",
            "/etc/passwd",
            "/root",
            "/home",
        ]

        try:
            with open("/proc/self/mounts", "r") as f:
                mounts = f.read()

            for path in sensitive_paths:
                if path in mounts or os.path.exists(path):
                    self.info.host_paths.append(path)

        except (FileNotFoundError, PermissionError):
            pass

    def _check_devices(self):
        """Check for accessible devices."""
        interesting_devices = [
            "/dev/mem",
            "/dev/kmem",
            "/dev/port",
            "/dev/sda",
            "/dev/nvme0n1",
            "/dev/vda",
        ]

        for dev in interesting_devices:
            if os.path.exists(dev):
                try:
                    # Check if readable
                    if os.access(dev, os.R_OK):
                        self.info.devices.append(dev)
                except OSError:
                    pass

    def _assess_escape_potential(self):
        """Assess likelihood of container escape."""
        score = 0
        reasons = []

        # Critical escape vectors
        if "/var/run/docker.sock" in self.info.host_paths:
            score += 100
            reasons.append("Docker socket mounted")

        if self.info.privileged:
            score += 90
            reasons.append("Privileged container")

        if "CAP_SYS_ADMIN" in self.info.capabilities:
            score += 70
            reasons.append("CAP_SYS_ADMIN available")

        if "CAP_SYS_PTRACE" in self.info.capabilities:
            score += 50
            reasons.append("CAP_SYS_PTRACE available")

        if not self.info.seccomp_enabled:
            score += 40
            reasons.append("Seccomp disabled")

        if self.info.devices:
            score += 60
            reasons.append(f"Host devices accessible: {self.info.devices}")

        if not self.info.namespaces.get("pid", True):
            score += 30
            reasons.append("Shared PID namespace")

        if not self.info.namespaces.get("net", True):
            score += 20
            reasons.append("Shared network namespace")

        # Assess overall potential
        if score >= 80:
            self.info.escape_potential = "critical"
        elif score >= 50:
            self.info.escape_potential = "high"
        elif score >= 25:
            self.info.escape_potential = "medium"
        else:
            self.info.escape_potential = "low"

        if reasons:
            logger.info(f"Escape potential: {self.info.escape_potential}")
            for reason in reasons:
                logger.debug(f"  - {reason}")

    def is_container(self) -> bool:
        """Check if running in any container."""
        return self.info.container_type != ContainerType.NONE

    def get_report(self) -> str:
        """Generate human-readable report."""
        lines = [
            "# Container Detection Report",
            "",
            f"Container Type: {self.info.container_type.name}",
            f"Container ID: {self.info.container_id or 'N/A'}",
            f"Hostname: {self.info.hostname}",
            f"Privileged: {self.info.privileged}",
            f"Escape Potential: {self.info.escape_potential.upper()}",
            "",
            "## Capabilities",
        ]

        for cap in self.info.capabilities:
            lines.append(f"  - {cap}")

        if not self.info.capabilities:
            lines.append("  (default)")

        lines.extend([
            "",
            "## Namespaces",
        ])

        for ns, isolated in self.info.namespaces.items():
            status = "isolated" if isolated else "SHARED WITH HOST"
            lines.append(f"  - {ns}: {status}")

        lines.extend([
            "",
            "## Security",
            f"  - Seccomp: {'enabled' if self.info.seccomp_enabled else 'DISABLED'}",
            f"  - AppArmor: {self.info.apparmor_profile or 'none'}",
            f"  - SELinux: {self.info.selinux_label or 'none'}",
            f"  - Cgroups: v{self.info.cgroups_version}",
            "",
            "## Sensitive Paths",
        ])

        for path in self.info.host_paths:
            lines.append(f"  - {path}")

        if not self.info.host_paths:
            lines.append("  (none detected)")

        lines.extend([
            "",
            "## Devices",
        ])

        for dev in self.info.devices:
            lines.append(f"  - {dev}")

        if not self.info.devices:
            lines.append("  (none accessible)")

        return "\n".join(lines)


def detect_container() -> ContainerInfo:
    """
    High-level function to detect container environment.

    Returns:
        ContainerInfo with detection results
    """
    detector = ContainerDetector()
    return detector.detect()
