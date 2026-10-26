"""Safely test Bayora audit-log tampering detection.

The original audit log is never modified. The test operates on a
temporary copy and removes that copy automatically when finished.
"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from pathlib import Path
import sys

# Add the project root to Python's import path.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from api.bayora_audit import verify_audit_log


def main() -> int:
    original_setting = os.environ.get("BAYORA_AUDIT_LOG")
    original_path = Path(
        original_setting or "data/bayora_audit.jsonl"
    ).resolve()

    print("\nBAYORA AUDIT TAMPERING TEST")
    print("=" * 60)
    print(f"Original log: {original_path}")

    if not original_path.is_file():
        print("[FAIL] Audit log file not found.")
        print("Check the log path before running this test.")
        return 2

    # Confirm that the original log is currently valid.
    original_result = verify_audit_log()

    if not original_result["valid"]:
        print("[FAIL] Original audit log is already invalid.")
        print(f"Reason: {original_result['error']}")
        print("Fix or investigate the original log before proceeding.")
        return 2

    print(
        f"[PASS] Original log verifies "
        f"({original_result['records_checked']} records)."
    )

    try:
        with tempfile.TemporaryDirectory(
            prefix="bayora_audit_test_"
        ) as temporary_directory:
            copied_path = Path(temporary_directory) / "tampered.jsonl"
            shutil.copy2(original_path, copied_path)

            lines = copied_path.read_text(
                encoding="utf-8"
            ).splitlines()

            if not lines:
                print("[FAIL] Audit log is empty; no record to modify.")
                return 2

            # Change a record field without updating its stored hash.
            record = json.loads(lines[0])

            if not isinstance(record, dict) or "hash" not in record:
                print("[FAIL] First record has an unexpected format.")
                return 2

            record["actor"] = str(record.get("actor", "")) + "_TAMPERED"
            lines[0] = json.dumps(
                record,
                sort_keys=True,
                ensure_ascii=False,
            )

            copied_path.write_text(
                "\n".join(lines) + "\n",
                encoding="utf-8",
            )

            print("[INFO] Modified the first record in the temporary copy.")
            print("[INFO] Verifying the modified copy...")

            # The verifier reads the temporary copy through its configured path.
            os.environ["BAYORA_AUDIT_LOG"] = str(copied_path)

            tampered_result = verify_audit_log()

            detected = (
                tampered_result["valid"] is False
                and tampered_result["error"] is not None
            )

            if detected:
                print("[PASS] Audit tampering was detected.")
                print(f"       Error: {tampered_result['error']}")
            else:
                print("[FAIL] The verifier did not detect the modification.")
                print(
                    f"       Result: "
                    f"{json.dumps(tampered_result, ensure_ascii=False)}"
                )
                return 1

        # TemporaryDirectory has now cleaned up the test copy.
        print("[PASS] Temporary test copy cleaned up.")
        print("[INFO] Original audit log was not modified.")
        print("\nResult: TAMPERING DETECTION TEST PASSED")
        return 0

    except (OSError, ValueError, TypeError) as exc:
        print(f"[ERROR] Test could not complete: {exc}")
        return 2

    finally:
        # Restore the environment used by the caller.
        if original_setting is None:
            os.environ.pop("BAYORA_AUDIT_LOG", None)
        else:
            os.environ["BAYORA_AUDIT_LOG"] = original_setting


if __name__ == "__main__":
    sys.exit(main())
