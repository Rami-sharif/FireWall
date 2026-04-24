"""
Structured firewall logging: terminal + file, optional clear on startup.
Log lines are readable and consistent for demo (e.g. [ALLOW], [BLOCK], [ALERT]).
"""

import logging
import sys
from pathlib import Path
from typing import Optional


def setup_firewall_logger(
    log_dir: Optional[str] = None,
    log_file: str = "firewall.log",
    clear_on_start: bool = False,
    level: int = logging.INFO,
) -> logging.Logger:
    """
    Configure firewall logger with file and console handlers.
    If clear_on_start is True, truncate the log file before first write.
    """
    name = "firewall_engine"
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)
    # Structured format for demo: [LEVEL] key=value ...
    formatter = logging.Formatter(
        "%(asctime)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File
    if log_dir:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        log_path = Path(log_dir) / log_file
        if clear_on_start and log_path.exists():
            try:
                log_path.write_text("", encoding="utf-8")
            except OSError:
                pass
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger


def get_firewall_logger() -> logging.Logger:
    """Return the firewall_engine logger (used by sniffer/detector)."""
    return logging.getLogger("firewall_engine")


def log_packet_action(
    action: str,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    reason: str = "",
    **kwargs: str | int | None,
) -> None:
    """
    Write a structured log line for packet action.
    action: ALLOW | BLOCK | ALERT | LOG_ONLY
    reason: exact reason for allow/block/alert.
    """
    logger = get_firewall_logger()
    parts = [f"[{action}]"]
    if src_ip is not None:
        parts.append(f"src={src_ip}")
    if dst_ip is not None:
        parts.append(f"dst={dst_ip}")
    if reason:
        parts.append(f"reason={reason}")
    for k, v in kwargs.items():
        if v is not None and v != "":
            parts.append(f"{k}={v}")
    logger.info(" ".join(parts))
