"""
Structured logging with verbosity levels for AutoPwn.
"""

import logging
import sys
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# Custom theme for exploit-related logging
AUTOPWN_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "exploit": "bold magenta",
    "vuln": "bold red",
    "gadget": "blue",
})

console = Console(theme=AUTOPWN_THEME)

# Log level mapping
LOG_LEVELS = {
    0: logging.WARNING,
    1: logging.INFO,
    2: logging.DEBUG,
}


def setup_logging(verbosity: int = 1, log_file: Optional[str] = None) -> None:
    """
    Configure logging for AutoPwn.

    Args:
        verbosity: 0=warning, 1=info, 2=debug
        log_file: Optional file path for logging output
    """
    level = LOG_LEVELS.get(verbosity, logging.DEBUG)

    handlers = [
        RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            rich_tracebacks=True,
            tracebacks_show_locals=verbosity >= 2,
        )
    ]

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
        )
        handlers.append(file_handler)

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
    )

    # Suppress noisy loggers
    logging.getLogger("angr").setLevel(logging.WARNING)
    logging.getLogger("cle").setLevel(logging.WARNING)
    logging.getLogger("pyvex").setLevel(logging.WARNING)
    logging.getLogger("claripy").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a module.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)


class ExploitLogger:
    """
    Specialized logger for exploit development with colored output.
    """

    def __init__(self, name: str):
        self.logger = get_logger(name)
        self.console = console

    def info(self, message: str) -> None:
        """Log info message."""
        self.logger.info(message)

    def debug(self, message: str) -> None:
        """Log debug message."""
        self.logger.debug(message)

    def warning(self, message: str) -> None:
        """Log warning message."""
        self.logger.warning(message)

    def error(self, message: str) -> None:
        """Log error message."""
        self.logger.error(message)

    def success(self, message: str) -> None:
        """Log success message with green color."""
        self.console.print(f"[success][+] {message}[/success]")
        self.logger.info(f"[SUCCESS] {message}")

    def exploit(self, message: str) -> None:
        """Log exploit-related message with magenta color."""
        self.console.print(f"[exploit][*] {message}[/exploit]")
        self.logger.info(f"[EXPLOIT] {message}")

    def vuln(self, message: str) -> None:
        """Log vulnerability-related message with red color."""
        self.console.print(f"[vuln][!] {message}[/vuln]")
        self.logger.info(f"[VULN] {message}")

    def gadget(self, address: int, instruction: str) -> None:
        """Log ROP gadget with blue color."""
        self.console.print(f"[gadget]  0x{address:x}: {instruction}[/gadget]")
        self.logger.debug(f"[GADGET] 0x{address:x}: {instruction}")

    def payload(self, data: bytes, max_len: int = 64) -> None:
        """Log payload bytes."""
        if len(data) > max_len:
            display = data[:max_len].hex() + "..."
        else:
            display = data.hex()
        self.console.print(f"[info]Payload ({len(data)} bytes): {display}[/info]")
