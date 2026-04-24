"""
Configuration loader: env and defaults.
Simulation mode ON and enforcement OFF by default (no destructive behavior).
"""

import os
from pathlib import Path

from app.utils.constants import (
    DATA_DIR,
    DB_FILENAME,
    DEFAULT_ICMP_FLOOD_THRESHOLD,
    DEFAULT_ICMP_FLOOD_WINDOW_SEC,
    DEFAULT_PORT_SCAN_THRESHOLD,
    DEFAULT_PORT_SCAN_WINDOW_SEC,
    DEFAULT_RATE_THRESHOLD,
    DEFAULT_SYN_FLOOD_THRESHOLD,
    DEFAULT_SYN_FLOOD_WINDOW_SEC,
    LOGS_DIR,
)


def _get_project_root() -> Path:
    """Project root: directory containing app/."""
    return Path(__file__).resolve().parent.parent.parent


def load_config() -> dict:
    """
    Load configuration from environment with safe defaults.
    - SIMULATION_MODE: default True (no real blocking).
    - ENFORCEMENT_ENABLED: default False (do not run iptables).
    - FIREWALL_DATA_DIR: optional override for data directory (e.g. for tests).
    """
    root = _get_project_root()
    data_path = os.environ.get("FIREWALL_DATA_DIR") or str(root / DATA_DIR)
    data_path = Path(data_path)
    logs_path = root / LOGS_DIR
    db_path = data_path / DB_FILENAME

    simulation = os.environ.get("SIMULATION_MODE", "true").lower() in ("true", "1", "yes")
    enforcement = os.environ.get("ENFORCEMENT_ENABLED", "false").lower() in ("true", "1", "yes")

    return {
        "SIMULATION_MODE": simulation,
        "ENFORCEMENT_ENABLED": enforcement and not simulation,
        "PROJECT_ROOT": str(root),
        "DATA_DIR": str(data_path),
        "LOGS_DIR": str(logs_path),
        "DB_PATH": str(db_path),
        "WHITELIST_PATH": str(Path(data_path) / "whitelist.txt"),
        "BLACKLIST_PATH": str(Path(data_path) / "blacklist.txt"),
        "DEFAULT_RULES_PATH": str(Path(data_path) / "default_rules.json"),
        "RATE_THRESHOLD": int(os.environ.get("RATE_THRESHOLD", DEFAULT_RATE_THRESHOLD)),
        "SYN_FLOOD_WINDOW_SEC": float(os.environ.get("SYN_FLOOD_WINDOW_SEC", DEFAULT_SYN_FLOOD_WINDOW_SEC)),
        "SYN_FLOOD_THRESHOLD": int(os.environ.get("SYN_FLOOD_THRESHOLD", DEFAULT_SYN_FLOOD_THRESHOLD)),
        "ICMP_FLOOD_WINDOW_SEC": float(os.environ.get("ICMP_FLOOD_WINDOW_SEC", DEFAULT_ICMP_FLOOD_WINDOW_SEC)),
        "ICMP_FLOOD_THRESHOLD": int(os.environ.get("ICMP_FLOOD_THRESHOLD", DEFAULT_ICMP_FLOOD_THRESHOLD)),
        "PORT_SCAN_WINDOW_SEC": float(os.environ.get("PORT_SCAN_WINDOW_SEC", DEFAULT_PORT_SCAN_WINDOW_SEC)),
        "PORT_SCAN_THRESHOLD": int(os.environ.get("PORT_SCAN_THRESHOLD", DEFAULT_PORT_SCAN_THRESHOLD)),
        "SUBPROCESS_TIMEOUT_SEC": int(os.environ.get("SUBPROCESS_TIMEOUT_SEC", 5)),
    }


# Singleton config (loaded on first use)
_config = None


def get_config() -> dict:
    global _config
    if _config is None:
        _config = load_config()
    return _config


def set_enforcement(simulation_mode: bool, enforcement_enabled: bool) -> None:
    """Runtime toggle for simulation/enforcement mode. Takes effect immediately."""
    cfg = get_config()
    cfg["SIMULATION_MODE"] = simulation_mode
    cfg["ENFORCEMENT_ENABLED"] = enforcement_enabled and not simulation_mode
