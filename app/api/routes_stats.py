"""
Flask routes: stats and traffic top-sources.
"""

from flask import Blueprint, request, jsonify

from app.services.stats_service import get_stats_from_logs, get_top_sources

bp = Blueprint("stats", __name__, url_prefix="/api")


@bp.route("/stats", methods=["GET"])
def stats():
    data = get_stats_from_logs()
    return jsonify(data)


@bp.route("/traffic/top-sources", methods=["GET"])
def top_sources():
    limit = min(int(request.args.get("limit", 10)), 100)
    items = get_top_sources(limit=limit)
    return jsonify({"items": items})
