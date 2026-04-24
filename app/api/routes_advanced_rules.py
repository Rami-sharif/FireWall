"""
Advanced rules API: tags, groups, validate, test, bulk, clone, history, import, export.
"""

import json
from flask import Blueprint, jsonify, request, Response

from app.services.rule_service import (
    get_all_tags,
    get_all_groups,
    get_rule_by_id,
    validate_rule_data,
    bulk_create_rules,
    clone_rule,
    get_rule_history,
    patch_rule_enabled,
    patch_rule_priority,
    patch_rule_tags,
    export_rules_json,
    export_rules_csv,
    import_rules_json,
    import_rules_csv,
    archive_rule,
)

bp = Blueprint("advanced_rules", __name__, url_prefix="/api/rules")


# ── Meta ──────────────────────────────────────────────────────────────────────

@bp.route("/tags", methods=["GET"])
def list_tags():
    return jsonify(get_all_tags())


@bp.route("/groups", methods=["GET"])
def list_groups():
    return jsonify(get_all_groups())


# ── Validate / Test ───────────────────────────────────────────────────────────

@bp.route("/validate", methods=["POST"])
def validate():
    data = request.get_json(force=True, silent=True) or {}
    result = validate_rule_data(data)
    return jsonify(result), (200 if result["valid"] else 422)


@bp.route("/test", methods=["POST"])
def test_rule():
    """
    Test a rule definition against a sample packet dict.
    Body: { "rule": {...}, "packet": {"src_ip":..., "dst_ip":..., "protocol":..., ...} }
    """
    body = request.get_json(force=True, silent=True) or {}
    rule_data = body.get("rule", {})
    packet = body.get("packet", {})

    # Quick validation
    val = validate_rule_data(rule_data)
    if not val["valid"]:
        return jsonify({"error": "Invalid rule", "details": val["errors"]}), 422

    # Build a transient Rule-like object
    from types import SimpleNamespace
    from app.engine.rule_engine import _rule_matches
    rule_ns = SimpleNamespace(
        src_ip=rule_data.get("src_ip"),
        dst_ip=rule_data.get("dst_ip"),
        protocol=rule_data.get("protocol"),
        src_port=rule_data.get("src_port"),
        dst_port=rule_data.get("dst_port"),
        payload_pattern=rule_data.get("payload_pattern"),
        payload_regex=bool(rule_data.get("payload_regex", False)),
        match_case_sensitive=bool(rule_data.get("match_case_sensitive", False)),
        tcp_flags=rule_data.get("tcp_flags"),
        rate_limit=rule_data.get("rate_limit"),
        time_range=rule_data.get("time_range"),
    )
    matched = _rule_matches(rule_ns, packet, packet.get("detection_tags", []))
    return jsonify({"matched": matched, "packet": packet})


# ── Bulk create ───────────────────────────────────────────────────────────────

@bp.route("/bulk", methods=["POST"])
def bulk_create():
    data = request.get_json(force=True, silent=True) or {}
    items = data if isinstance(data, list) else data.get("rules", [])
    result = bulk_create_rules(items)
    status = 201 if result["created"] > 0 else 422
    return jsonify(result), status


# ── Per-rule patch endpoints ──────────────────────────────────────────────────

@bp.route("/<int:rule_id>/enabled", methods=["PATCH"])
def patch_enabled(rule_id):
    body = request.get_json(force=True, silent=True) or {}
    enabled = bool(body.get("enabled", True))
    r = patch_rule_enabled(rule_id, enabled)
    if not r:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify(r.to_dict())


@bp.route("/<int:rule_id>/priority", methods=["PATCH"])
def patch_priority(rule_id):
    body = request.get_json(force=True, silent=True) or {}
    try:
        priority = int(body["priority"])
    except (KeyError, ValueError, TypeError):
        return jsonify({"error": "priority must be an integer"}), 422
    r = patch_rule_priority(rule_id, priority)
    if not r:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify(r.to_dict())


@bp.route("/<int:rule_id>/tags", methods=["PATCH"])
def patch_tags(rule_id):
    body = request.get_json(force=True, silent=True) or {}
    tags = body.get("tags", [])
    if not isinstance(tags, list):
        return jsonify({"error": "tags must be a list"}), 422
    r = patch_rule_tags(rule_id, [str(t) for t in tags])
    if not r:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify(r.to_dict())


@bp.route("/<int:rule_id>/archive", methods=["POST"])
def archive(rule_id):
    r = archive_rule(rule_id)
    if not r:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify(r.to_dict())


# ── Clone ─────────────────────────────────────────────────────────────────────

@bp.route("/<int:rule_id>/clone", methods=["POST"])
def clone(rule_id):
    body = request.get_json(force=True, silent=True) or {}
    new_name = body.get("name") or None
    r = clone_rule(rule_id, new_name)
    if not r:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify(r.to_dict()), 201


# ── History ───────────────────────────────────────────────────────────────────

@bp.route("/<int:rule_id>/history", methods=["GET"])
def history(rule_id):
    log = get_rule_history(rule_id)
    if log is None:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify({"rule_id": rule_id, "history": log})


# ── Export ────────────────────────────────────────────────────────────────────

@bp.route("/export", methods=["GET"])
def export_rules():
    fmt = request.args.get("format", "json").lower()
    include_archived = request.args.get("include_archived", "false").lower() == "true"
    if fmt == "csv":
        content = export_rules_csv(include_archived=include_archived)
        return Response(
            content,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=rules.csv"},
        )
    content = export_rules_json(include_archived=include_archived)
    return Response(
        content,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=rules.json"},
    )


# ── Import ────────────────────────────────────────────────────────────────────

@bp.route("/import", methods=["POST"])
def import_rules():
    fmt = request.args.get("format", "json").lower()
    if request.content_type and "multipart" in request.content_type:
        f = request.files.get("file")
        if not f:
            return jsonify({"error": "No file uploaded"}), 400
        raw = f.read().decode("utf-8", errors="replace")
        fmt = "csv" if f.filename and f.filename.endswith(".csv") else "json"
    else:
        raw = request.get_data(as_text=True)
    if fmt == "csv":
        result = import_rules_csv(raw)
    else:
        result = import_rules_json(raw)
    return jsonify(result), (201 if result.get("created", 0) > 0 else 422)
