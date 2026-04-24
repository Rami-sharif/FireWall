"""
Application-wide constants for the Smart Firewall Simulation Platform.
"""

# Rule actions
ACTION_ALLOW = "ALLOW"
ACTION_BLOCK = "BLOCK"
ACTION_ALERT = "ALERT"
ACTION_LOG_ONLY = "LOG_ONLY"

ACTIONS = (ACTION_ALLOW, ACTION_BLOCK, ACTION_ALERT, ACTION_LOG_ONLY)

# Default thresholds (used when not in config)
DEFAULT_RATE_THRESHOLD = 40  # packets per second per source IP
DEFAULT_SYN_FLOOD_WINDOW_SEC = 1.0
DEFAULT_SYN_FLOOD_THRESHOLD = 30
DEFAULT_ICMP_FLOOD_WINDOW_SEC = 1.0
DEFAULT_ICMP_FLOOD_THRESHOLD = 50
DEFAULT_PORT_SCAN_WINDOW_SEC = 5.0
DEFAULT_PORT_SCAN_THRESHOLD = 10  # distinct ports in window
DEFAULT_PAYLOAD_SUMMARY_LEN = 200

# Time windows (seconds)
RATE_WINDOW_SEC = 1.0

# Paths (relative to project root)
DATA_DIR = "data"
LOGS_DIR = "logs"
REPORTS_DIR = "reports"
WHITELIST_FILE = "whitelist.txt"
BLACKLIST_FILE = "blacklist.txt"
DEFAULT_RULES_JSON = "default_rules.json"
DB_FILENAME = "firewall.db"

# Detection tags (used by detector and alerts)
DETECTION_RATE_LIMIT = "rate_limit"
DETECTION_SYN_FLOOD = "syn_flood"
DETECTION_ICMP_FLOOD = "icmp_flood"
DETECTION_PORT_SCAN = "port_scan"
DETECTION_SUSPICIOUS_PAYLOAD = "suspicious_payload"

# Alert severity
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

# Protocols (string names)
PROTOCOL_TCP = "TCP"
PROTOCOL_UDP = "UDP"
PROTOCOL_ICMP = "ICMP"
PROTOCOL_OTHER = "OTHER"
