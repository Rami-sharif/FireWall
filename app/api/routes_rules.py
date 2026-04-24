"""
Flask routes: rules CRUD.
"""

from flask import Blueprint, request, jsonify

from app.services.rule_service import get_all_rules, get_rule_by_id, create_rule, update_rule, delete_rule

bp = Blueprint("rules", __name__, url_prefix="/api/rules")


@bp.route("", methods=["GET"])
def list_rules():
    enabled_only = request.args.get("enabled") == "true"
    rules = get_all_rules(enabled_only=enabled_only)
    return jsonify([r.to_dict() for r in rules])


@bp.route("/<int:rule_id>", methods=["GET"])
def get_rule(rule_id):
    r = get_rule_by_id(rule_id)
    if not r:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify(r.to_dict())


@bp.route("", methods=["POST"])
def add_rule():
    data = request.get_json() or {}
    try:
        r = create_rule(data)
        return jsonify(r.to_dict()), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@bp.route("/<int:rule_id>", methods=["PUT"])
def patch_rule(rule_id):
    data = request.get_json() or {}
    r = update_rule(rule_id, data)
    if not r:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify(r.to_dict())


@bp.route("/<int:rule_id>", methods=["DELETE"])
def remove_rule(rule_id):
    if not delete_rule(rule_id):
        return jsonify({"error": "Rule not found"}), 404
    return jsonify({"ok": True}), 200
