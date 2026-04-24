# Smart Firewall Simulation Platform

A modular firewall simulation and traffic analysis platform for monitoring packets, applying security rules, detecting suspicious behavior, and visualizing results via a web dashboard. Suitable as a university graduation project.

## Features

- **Packet sniffing** using Scapy (IP layer)
- **Packet parsing**: source/dest IP, protocol, ports, length, TCP flags, payload summary
- **Blacklist and whitelist** (file-based)
- **Rule engine**: ALLOW, BLOCK, ALERT, LOG_ONLY with priority ordering
- **Detection**: rate limit, SYN flood-like, ICMP flood-like, port scan-like, suspicious payload (e.g. Nimda)
- **Simulation mode** (default): no real OS blocking; decisions are logged only
- **Enforcement mode** (optional): apply blocking via iptables on Linux when enabled
- **SQLite** storage for rules, traffic logs, alerts, and stats
- **Flask API** and **Bootstrap + Chart.js** dashboard

## Architecture

- **app/engine**: sniffer, parser, detector, rule_engine, enforcer, simulator
- **app/api**: REST routes for rules, logs, alerts, stats, control
- **app/db**: SQLAlchemy models and database init
- **app/services**: rule, log, alert, stats services
- **app/utils**: config, logger, helpers, constants
- **dashboard**: HTML templates and static assets

Data flow: Sniffer → Parser → Detector → Rule engine → Log/Alert/Stats → Enforcer (if BLOCK and enforcement enabled).

## Requirements

- Python 3.10+
- Linux recommended for full sniffing and enforcement; Windows can run with L3 socket (admin may be required) and no iptables

## Install

```bash
python -m venv venv
source venv/bin/activate   # Linux/macOS
# or: venv\Scripts\Activate.ps1   # Windows
pip install -r requirements.txt
```

## Run

```bash
python run.py
```

Then open: **http://127.0.0.1:5000**

- **Dashboard**: main stats, protocol distribution, top source IPs, sniffer Start/Stop
- **Rules**: add, list, delete rules
- **Logs**: traffic log table with pagination
- **Alerts**: security alerts table
- **Traffic**: top sources chart and stats

## Simulation mode (default)

- **SIMULATION_MODE** is true by default. No real firewall/iptables blocking is applied.
- All decisions (ALLOW, BLOCK, ALERT, LOG_ONLY) are recorded in the database and shown on the dashboard.
- Safe for demos and development.

## Enforcement mode

- Set **ENFORCEMENT_ENABLED=true** and **SIMULATION_MODE=false** (e.g. via environment variables) to enable real blocking.
- When a rule or blacklist results in BLOCK, the enforcer runs `iptables -A INPUT -s <ip> -j DROP` (Linux only, via subprocess with timeout).
- **Requires root** on Linux. Not enabled by default; use only in controlled environments.

## Sniffing and privileges

- **Linux**: Packet capture typically requires root (`sudo python run.py`). Enforcement (iptables) also requires root.
- **Windows**: Scapy uses L3 socket when Npcap is not installed; raw socket may require Administrator. For full capture, install Npcap.

## API endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/stats | Aggregate stats (total, allowed, blocked, alerts, protocol breakdown) |
| GET | /api/logs | Traffic logs (pagination, optional src_ip, action) |
| GET | /api/alerts | Alerts (pagination, optional severity) |
| GET | /api/rules | List rules |
| POST | /api/rules | Create rule |
| PUT | /api/rules/<id> | Update rule |
| DELETE | /api/rules/<id> | Delete rule |
| GET | /api/traffic/top-sources | Top source IPs by packet count |
| POST | /api/control/start | Start sniffer |
| POST | /api/control/stop | Stop sniffer |
| GET | /api/control/status | Sniffer running status |

## Testing and simulation

- **Unit tests** (rule engine, parser):
  ```bash
  pytest tests/ -v
  ```

- **Packet simulator** (generate traffic for demos):
  ```bash
  python -m app.engine.simulator --target 127.0.0.1 --scenario syn_flood --count 50
  python -m app.engine.simulator --target 127.0.0.1 --scenario icmp_flood --count 50
  python -m app.engine.simulator --target 127.0.0.1 --scenario suspicious_payload
  python -m app.engine.simulator --target 127.0.0.1 --scenario repeated --count 30
  ```

Scenarios: `normal`, `icmp_flood`, `syn_flood`, `suspicious_payload`, `repeated`.

## Folder structure

```
firewall_project/
├── app/
│   ├── engine/       # sniffer, parser, detector, rule_engine, enforcer, simulator
│   ├── api/          # Flask route modules
│   ├── db/           # database.py, models.py
│   ├── services/     # rule, log, alert, stats
│   ├── utils/        # config, logger, helpers, constants
│   └── main.py
├── dashboard/
│   ├── templates/    # base, index, rules, logs, alerts, traffic
│   └── static/       # css, js
├── data/             # whitelist.txt, blacklist.txt, default_rules.json
├── logs/             # application log file
├── reports/
├── tests/
├── requirements.txt
├── run.py
└── README.md
```

## Configuration

Environment variables (optional):

- **SIMULATION_MODE**: default `true`
- **ENFORCEMENT_ENABLED**: default `false`
- **RATE_THRESHOLD**: packets per second per IP (default 40)
- **SYN_FLOOD_THRESHOLD**, **ICMP_FLOOD_THRESHOLD**, **PORT_SCAN_THRESHOLD**: detection limits
- **DB_PATH**, **DATA_DIR**, **LOGS_DIR**: overridden by config from project paths if not set

## License

Project for educational use (graduation project).
