
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
    "BAYORA_API_URL",
    "http://127.0.0.1:8000",
).rstrip("/")

RED_TOKEN = os.getenv("BAYORA_RED_TEAM_TOKEN")
BLUE_TOKEN = os.getenv("BAYORA_BLUE_TEAM_TOKEN")
ADMIN_TOKEN = os.getenv("BAYORA_AUDIT_ADMIN_TOKEN")

results = []


def request_api(
    path: str,
    token: str | None = None,
    method: str = "GET",
    payload: dict | None = None,
) -> tuple[int, dict]:
    """Send an HTTP request with optional Bearer authentication and JSON."""
    headers = {
        "Accept": "application/json",
    }

    if token:
        headers["Authorization"] = f"Bearer {token}"

    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")

    request = Request(
        f"{BASE_URL}{path}",
        data=data,
        headers=headers,
        method=method.upper(),
    )

    try:
        with urlopen(request, timeout=10) as response:
            status = response.status
            body = response.read().decode("utf-8", errors="replace")

    except HTTPError as exc:
        status = exc.code
        body = exc.read().decode("utf-8", errors="replace")

    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(
            f"Cannot reach {BASE_URL}: {exc}"
        ) from exc

    try:
        parsed = json.loads(body) if body else {}
    except json.JSONDecodeError:
        parsed = {"raw_response": body}

    if not isinstance(parsed, dict):
        parsed = {"response": parsed}

    return status, parsed


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
    expected = (
        (expected_status,)
        if isinstance(expected_status, int)
        else expected_status
    )

    status, body = request_api(path, token=token)
    passed = status in expected

    expected_text = " or ".join(str(code) for code in expected)

    check(
        name,
        passed,
        f"expected HTTP {expected_text}, received HTTP {status}",
    )

    if not passed:
        print(
            "       Response:",
            json.dumps(body, ensure_ascii=False),
        )


def run_audit_check() -> None:
    """Verify audit-chain integrity using the POST endpoint."""
    status, body = request_api(
        "/bayora/audit/verify",
        token=ADMIN_TOKEN,
        method="POST",
        payload={},
    )

    valid = status == 200 and body.get("valid") is True

    detail = (
        f"HTTP {status}; "
        f"valid={body.get('valid')}; "
        f"records_checked={body.get('records_checked')}; "
        f"error={body.get('error')}"
    )

    check("Audit chain verifies", valid, detail)

    if status != 200:
        print(
            "       Response:",
            json.dumps(body, ensure_ascii=False),
        )


def main() -> int:
    global results
    results = []

    required_tokens = {
        "BAYORA_RED_TEAM_TOKEN": RED_TOKEN,
        "BAYORA_BLUE_TEAM_TOKEN": BLUE_TOKEN,
        "BAYORA_AUDIT_ADMIN_TOKEN": ADMIN_TOKEN,
    }

    missing = [
        name
        for name, value in required_tokens.items()
        if not value
    ]

    if missing:
        print("Missing required environment variables:")
        for name in missing:
            print(f"  - {name}")

        print(
            "\nSet the tokens in this PowerShell session "
            "and run the script again."
        )
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
        run_audit_check()
    except RuntimeError as exc:
        print(f"\nERROR: {exc}")
        return 2

    passed = sum(item["passed"] for item in results)
    failed = len(results) - passed

    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))

    report_path = os.path.join(
        project_root,
        "reports",
        "bayora_security_demo.json",
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
