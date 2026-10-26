
"""Tamper-evident JSONL audit logging for the Bayora prototype."""

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_DEFAULT_LOG_PATH = Path("data") / "bayora_audit.jsonl"
_GENESIS_HASH = "0" * 64
_LOCK = threading.Lock()


def _log_path() -> Path:
    """Resolve the log path, allowing tests to use temporary files."""
    return Path(os.getenv("BAYORA_AUDIT_LOG", str(_DEFAULT_LOG_PATH)))


def _canonical_json(record: dict[str, Any]) -> bytes:
    """Serialize a record consistently for reproducible hashing."""
    return json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _calculate_hash(record: dict[str, Any]) -> str:
    """Calculate the SHA-256 hash of a record."""
    return hashlib.sha256(_canonical_json(record)).hexdigest()


def verify_audit_log() -> dict[str, Any]:
    """Verify every record's hash and its link to the preceding record."""
    path = _log_path()

    if not path.exists():
        return {
            "valid": True,
            "records_checked": 0,
            "error": None,
        }

    previous_hash = _GENESIS_HASH
    records_checked = 0

    try:
        with path.open("r", encoding="utf-8") as audit_file:
            for line_number, line in enumerate(audit_file, start=1):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    return {
                        "valid": False,
                        "records_checked": records_checked,
                        "error": f"Invalid JSON on line {line_number}",
                    }

                if not isinstance(record, dict):
                    return {
                        "valid": False,
                        "records_checked": records_checked,
                        "error": f"Invalid record on line {line_number}",
                    }

                stored_hash = record.get("hash")
                stored_previous_hash = record.get("previous_hash")

                if not isinstance(stored_hash, str):
                    return {
                        "valid": False,
                        "records_checked": records_checked,
                        "error": f"Missing or invalid hash on line {line_number}",
                    }

                if stored_previous_hash != previous_hash:
                    return {
                        "valid": False,
                        "records_checked": records_checked,
                        "error": f"Hash-chain mismatch on line {line_number}",
                    }

                unhashed_record = {
                    key: value
                    for key, value in record.items()
                    if key != "hash"
                }

                calculated_hash = _calculate_hash(unhashed_record)

                if not hmac.compare_digest(stored_hash, calculated_hash):
                    return {
                        "valid": False,
                        "records_checked": records_checked,
                        "error": f"Record hash mismatch on line {line_number}",
                    }

                previous_hash = stored_hash
                records_checked += 1

    except (OSError, UnicodeDecodeError) as exc:
        return {
            "valid": False,
            "records_checked": records_checked,
            "error": f"Could not read audit log: {exc}",
        }

    return {
        "valid": True,
        "records_checked": records_checked,
        "error": None,
    }


def record_audit_event(
    *,
    request_id: str | None,
    actor: str,
    target: str,
    outcome: str,
    event_type: str = "resource_access",
) -> dict[str, Any]:
    """Append an audit event, refusing to extend an invalid log."""
    path = _log_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    with _LOCK:
        verification = verify_audit_log()

        if not verification["valid"]:
            raise RuntimeError(
                "Audit log integrity check failed: "
                f"{verification['error']}"
            )

        previous_hash = _GENESIS_HASH

        if path.exists() and path.stat().st_size > 0:
            with path.open("r", encoding="utf-8") as audit_file:
                for line in audit_file:
                    if line.strip():
                        last_record = json.loads(line)

            previous_hash = last_record["hash"]

        record: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "actor": actor,
            "target": target,
            "outcome": outcome,
            "event_type": event_type,
            "previous_hash": previous_hash,
        }

        record["hash"] = _calculate_hash(record)

        with path.open(
            "a",
            encoding="utf-8",
            newline="\n",
        ) as audit_file:
            audit_file.write(
                json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n"
            )
            audit_file.flush()
            os.fsync(audit_file.fileno())

        return record
