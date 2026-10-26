"""Bayora security verification demo.

Checks:
1. Red team can access its own resource.
2. Red team cannot access blue team's resource.
3. Blue team can access its own resource.
4. Blue team cannot access red team's resource.
5. Unauthenticated requests are rejected.
6. Audit-chain integrity verifies.

Scope: Application-level authorization and audit verification.
This does not prove OS/container isolation.

Uses only the Python standard library.
"""

import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE_URL = os.getenv(
    "BAYORA_API_URL", "http://127.0.0.1:8000"
).rstrip("/")

RED_TOKEN = os.getenv("BAYORA_RED_TEAM_TOKEN")
BLUE_TOKEN = os.getenv("BAYORA_BLUE_TEAM_TOKEN")
ADMIN_TOKEN = os.getenv("BAYORA_AUDIT_ADMIN_TOKEN")

results = []


def request_api(path: str, token: str | None = None) -> tuple[int, dict]:
    """Send a GET request, optionally with a bearer token."""
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"

    request = Request(
        f"{BASE_URL}{path}",
        headers=headers,
        method="GET",
    )

    try:
        with urlopen(request, timeout=10) as response:
            status = response.status
            body = response.read().decode("utf-8")
    except HTTPError as exc:
        status = exc.code
        body = exc.read().decode("utf-8", errors="replace")
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(
            f"Cannot reach {BASE_URL}: {exc}"
        ) from exc

    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        data = {"raw_response": body}

    if not isinstance(data, dict):
        data = {"response": data}

    return status, data


def check(name: str, passed: bool, detail: str) -> None:
    """Record and print one verification result."""
    results.append({
        "check": name,
        "passed": passed,
        "detail": detail,
    })
    label = "PASS" if passed else "FAIL"
    print(f"[{label}] {name}: {detail}")


def run_check(
    name: str,
    path: str,
    token: str | None,
    expected_status: int | tuple[int, ...],
) -> None:
    """Execute one HTTP status assertion."""
    if isinstance(expected_status, int):
        expected = (expected_status,)
    else:
        expected = expected_status

    status, body = request_api(path, token)
    passed = status in expected

    expected_text = " or ".join(str(code) for code in expected)
    check(
        name,
        passed,
        f"expected HTTP {expected_text}, received HTTP {status}",
    )

    if not passed:
        print(f"       Response: {json.dumps(body, ensure_ascii=False)}")


def main() -> int:
    global results
    results = []

    missing = [
        name
        for name, value in (
            ("BAYORA_RED_TEAM_TOKEN", RED_TOKEN),
            ("BAYORA_BLUE_TEAM_TOKEN", BLUE_TOKEN),
            ("BAYORA_AUDIT_ADMIN_TOKEN", ADMIN_TOKEN),
        )
        if not value
    ]

    if missing:
        print("Missing required environment variables:")
        for name in missing:
            print(f"  - {name}")
        print("Set them in this PowerShell session and retry.")
        return 2

    if RED_TOKEN == BLUE_TOKEN:
        print("FAIL: Red and blue team tokens must differ.")
        return 2

    print("\nBAYORA SECURITY VERIFICATION")
    print("=" * 64)
    print(f"API: {BASE_URL}")
    print("Testing application-level access boundaries...\n")

    checks = [
        (
            "Red team can access red resource",
            "/bayora/private/red",
            RED_TOKEN,
            200,
        ),
        (
            "Red team cannot access blue resource",
            "/bayora/private/blue",
            RED_TOKEN,
            403,
        ),
        (
            "Blue team can access blue resource",
            "/bayora/private/blue",
            BLUE_TOKEN,
            200,
        ),
        (
            "Blue team cannot access red resource",
            "/bayora/private/red",
            BLUE_TOKEN,
            403,
        ),
        (
            "Unauthenticated request is rejected",
            "/bayora/private/red",
            None,
            (401, 403),
        ),
    ]

    for name, path, token, expected_status in checks:
        try:
            run_check(name, path, token, expected_status)
        except RuntimeError as exc:
            print(f"\nERROR: {exc}")
            return 2

    print("\nChecking audit-chain integrity...\n")

    try:
        status, body = request_api(
            "/bayora/audit/verify", ADMIN_TOKEN
        )
        valid = status == 200 and body.get("valid") is True

        check(
            "Audit chain verifies",
            valid,
            (
                f"HTTP {status}; valid={body.get('valid')}; "
                f"records_checked={body.get('records_checked')}; "
                f"error={body.get('error')}"
            ),
        )
    except RuntimeError as exc:
        print(f"\nERROR: {exc}")
        return 2

    passed = sum(item["passed"] for item in results)
    failed = len(results) - passed

    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_path = os.path.join(
        project_root, "reports", "bayora_security_demo.json"
    )
    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    report = {
        "endpoint": BASE_URL,
        "checks_passed": passed,
        "checks_failed": failed,
        "total_checks": len(results),
        "results": results,
        "scope": (
            "Application-level authorization and audit verification; "
            "not proof of OS, container, or network isolation."
        ),
    }

    with open(report_path, "w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2)
        report_file.write("\n")

    print("\n" + "=" * 64)
    print(f"Checks passed: {passed}/{len(results)}")
    print(f"Checks failed: {failed}")
    print(f"Report: {report_path}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
