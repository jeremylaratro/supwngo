"""
AutoPwn - Automated Binary Exploitation Framework

A comprehensive, modular automated binary exploitation framework that integrates
fuzzing, symbolic execution, vulnerability detection, and automatic exploit
generation into a unified pipeline.
"""

__version__ = "1.0.0"
__author__ = "AutoPwn Team"

from autopwn.core.binary import Binary
from autopwn.core.context import ExploitContext
from autopwn.core.database import Database

__all__ = [
    "Binary",
    "ExploitContext",
    "Database",
    "__version__",
]
