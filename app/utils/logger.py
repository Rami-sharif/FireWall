"""
Centralized Python logging: file + console.
"""

import logging
import sys
from pathlib import Path


def setup_logger(
    name: str = "firewall",
    log_dir: str | None = None,
    level: int = logging.INFO,
) -> logging.Logger:
    """
    Configure and return a logger with file and console handlers.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File (optional)
    if log_dir:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(Path(log_dir) / "firewall.log", encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger


def get_logger(name: str = "firewall") -> logging.Logger:
    """Return existing logger or create with default config (no file until app sets log dir)."""
    log = logging.getLogger(name)
    if not log.handlers:
        setup_logger(name, log_dir=None, level=logging.INFO)
    return log
