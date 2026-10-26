
import pytest
from fastapi import HTTPException
from starlette.requests import Request

from api.bayora_security import enforce_team_rate_limit


def make_request() -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/bayora/private/red",
        "headers": [],
        "query_string": b"",
        "server": ("testserver", 80),
        "client": ("testclient", 12345),
        "scheme": "http",
        "http_version": "1.1",
        "state": {"request_id": "rate-limit-test"},
    }
    return Request(scope)


@pytest.fixture(autouse=True)
def configure_rate_limit(monkeypatch):
    from api import bayora_security

    # Isolate every test from prior requests.
    with bayora_security._rate_limit_lock:
        bayora_security._team_request_counts.clear()

    monkeypatch.setenv("BAYORA_RATE_LIMIT_REQUESTS", "2")
    monkeypatch.setenv("BAYORA_RATE_LIMIT_WINDOW_SECONDS", "60")

    yield

    with bayora_security._rate_limit_lock:
        bayora_security._team_request_counts.clear()


def test_requests_within_limit_are_allowed():
    request = make_request()

    assert enforce_team_rate_limit(request, "red") == "red"
    assert enforce_team_rate_limit(request, "red") == "red"


def test_exceeding_limit_returns_429():
    request = make_request()

    enforce_team_rate_limit(request, "red")
    enforce_team_rate_limit(request, "red")

    with pytest.raises(HTTPException) as exc:
        enforce_team_rate_limit(request, "red")

    assert exc.value.status_code == 429
    assert "Retry-After" in exc.value.headers


def test_each_team_has_an_independent_limit():
    request = make_request()

    enforce_team_rate_limit(request, "red")
    enforce_team_rate_limit(request, "red")

    # Red is at its limit, but blue has a separate counter.
    assert enforce_team_rate_limit(request, "blue") == "blue"


def test_expired_window_resets_counter(monkeypatch):
    from api import bayora_security

    current_time = [100.0]
    monkeypatch.setattr(
        bayora_security.time,
        "monotonic",
        lambda: current_time[0],
    )

    request = make_request()

    enforce_team_rate_limit(request, "red")
    enforce_team_rate_limit(request, "red")

    with pytest.raises(HTTPException):
        enforce_team_rate_limit(request, "red")

    # Advance beyond the 60-second window.
    current_time[0] = 161.0

    assert enforce_team_rate_limit(request, "red") == "red"
