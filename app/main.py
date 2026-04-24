"""
Flask application: init DB, register blueprints, dashboard routes.
"""

import os
from pathlib import Path

from flask import Flask, render_template

from app.db.database import init_db
from app.utils.config import get_config
from app.utils.logger import setup_logger

# Config and logging
config = get_config()
Path(config["LOGS_DIR"]).mkdir(parents=True, exist_ok=True)
Path(config["DATA_DIR"]).mkdir(parents=True, exist_ok=True)
setup_logger("firewall", log_dir=config["LOGS_DIR"])

# Create app
app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard", "templates"),
    static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard", "static"),
    static_url_path="/static",
)

# Init DB on startup (creates tables + migrates new columns)
with app.app_context():
    init_db()
    default_rules_path = config.get("DEFAULT_RULES_PATH")
    if default_rules_path and Path(default_rules_path).exists():
        from app.services.rule_service import load_rules_from_json
        load_rules_from_json(default_rules_path)

# Register API blueprints
from app.api.routes_rules import bp as rules_bp
from app.api.routes_logs import bp as logs_bp
from app.api.routes_alerts import bp as alerts_bp
from app.api.routes_stats import bp as stats_bp
from app.api.routes_control import bp as control_bp
from app.api.routes_advanced_rules import bp as advanced_rules_bp
from app.api.routes_data_management import bp as data_mgmt_bp

app.register_blueprint(rules_bp)
app.register_blueprint(logs_bp)
app.register_blueprint(alerts_bp)
app.register_blueprint(stats_bp)
app.register_blueprint(control_bp)
app.register_blueprint(advanced_rules_bp)
app.register_blueprint(data_mgmt_bp)


# Dashboard page routes
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/rules")
def rules_page():
    return render_template("rules.html")


@app.route("/logs")
def logs_page():
    return render_template("logs.html")


@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html")


@app.route("/traffic")
def traffic_page():
    return render_template("traffic.html")


@app.route("/data-management")
def data_management_page():
    return render_template("data_management.html")


@app.route("/blocked")
def blocked_page():
    return render_template("blocked.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
