
"""Tests for Bayora's tamper-evident audit log."""

import json

from api.bayora_audit import record_audit_event, verify_audit_log


def test_empty_log_is_valid(monkeypatch, tmp_path):
    monkeypatch.setenv("BAYORA_AUDIT_LOG", str(tmp_path / "audit.jsonl"))

    result = verify_audit_log()

    assert result["valid"] is True
    assert result["records_checked"] == 0


def test_appended_records_form_valid_hash_chain(monkeypatch, tmp_path):
    monkeypatch.setenv("BAYORA_AUDIT_LOG", str(tmp_path / "audit.jsonl"))

    record_audit_event(
        request_id="request-1",
        actor="red",
        target="red",
        outcome="allowed",
    )
    record_audit_event(
        request_id="request-2",
        actor="red",
        target="blue",
        outcome="denied",
        event_type="cross_team_access",
    )

    result = verify_audit_log()

    assert result["valid"] is True
    assert result["records_checked"] == 2


def test_modified_record_is_detected(monkeypatch, tmp_path):
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("BAYORA_AUDIT_LOG", str(path))

    record_audit_event(
        request_id="request-1",
        actor="red",
        target="red",
        outcome="allowed",
    )

    records = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    records[0]["outcome"] = "denied"
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    result = verify_audit_log()

    assert result["valid"] is False
    assert "mismatch" in result["error"].lower()


def test_appending_to_tampered_log_is_rejected(monkeypatch, tmp_path):
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("BAYORA_AUDIT_LOG", str(path))

    record_audit_event(
        request_id="request-1",
        actor="red",
        target="red",
        outcome="allowed",
    )

    records = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    records[0]["outcome"] = "tampered"
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    try:
        record_audit_event(
            request_id="request-2",
            actor="red",
            target="blue",
            outcome="denied",
        )
    except RuntimeError as exc:
        assert "integrity check failed" in str(exc).lower()
    else:
        raise AssertionError("Expected a tampered log to be rejected")

def test_tampered_audit_record_is_detected(tmp_path, monkeypatch):
    import json

    from api.bayora_audit import record_audit_event, verify_audit_log

    # Use a temporary audit log, not the real project log.
    audit_file = tmp_path / "tampered_audit.jsonl"
    monkeypatch.setenv("BAYORA_AUDIT_LOG", str(audit_file))

    # Create a legitimate audit event.
    record_audit_event(
        request_id="tamper-test-001",
        actor="red",
        target="red",
        outcome="allowed",
        event_type="resource_access",
    )

    # Change the event without updating its stored hash.
    record = json.loads(audit_file.read_text(encoding="utf-8"))
    record["actor"] = "blue"

    audit_file.write_text(
        json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    # The verifier must detect the modification.
    result = verify_audit_log()

    assert result["valid"] is False
    assert "hash mismatch" in result["error"].lower()
