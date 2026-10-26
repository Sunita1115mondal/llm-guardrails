
"""Tests for Bayora team access control."""

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)

RED_HEADERS = {"Authorization": "Bearer dev-red-token-change-me"}
BLUE_HEADERS = {"Authorization": "Bearer dev-blue-token-change-me"}


def test_missing_token_is_rejected(monkeypatch):
    monkeypatch.setenv("BAYORA_RED_TEAM_TOKEN", "red-test-secret")
    monkeypatch.setenv("BAYORA_BLUE_TEAM_TOKEN", "blue-test-secret")

    response = client.get("/bayora/private/red")

    assert response.status_code == 401


def test_red_team_can_access_red_resource(monkeypatch):
    monkeypatch.setenv("BAYORA_RED_TEAM_TOKEN", "dev-red-token-change-me")
    monkeypatch.setenv("BAYORA_BLUE_TEAM_TOKEN", "dev-blue-token-change-me")

    response = client.get("/bayora/private/red", headers=RED_HEADERS)

    assert response.status_code == 200
    assert response.json()["team"] == "red"


def test_blue_team_can_access_blue_resource(monkeypatch):
    monkeypatch.setenv("BAYORA_RED_TEAM_TOKEN", "dev-red-token-change-me")
    monkeypatch.setenv("BAYORA_BLUE_TEAM_TOKEN", "dev-blue-token-change-me")

    response = client.get("/bayora/private/blue", headers=BLUE_HEADERS)

    assert response.status_code == 200
    assert response.json()["team"] == "blue"


def test_red_team_cannot_access_blue_resource(monkeypatch):
    monkeypatch.setenv("BAYORA_RED_TEAM_TOKEN", "dev-red-token-change-me")
    monkeypatch.setenv("BAYORA_BLUE_TEAM_TOKEN", "dev-blue-token-change-me")

    response = client.get("/bayora/private/blue", headers=RED_HEADERS)

    assert response.status_code == 403


def test_blue_team_cannot_access_red_resource(monkeypatch):
    monkeypatch.setenv("BAYORA_RED_TEAM_TOKEN", "dev-red-token-change-me")
    monkeypatch.setenv("BAYORA_BLUE_TEAM_TOKEN", "dev-blue-token-change-me")

    response = client.get("/bayora/private/red", headers=BLUE_HEADERS)

    assert response.status_code == 403


def test_invalid_token_is_rejected(monkeypatch):
    monkeypatch.setenv("BAYORA_RED_TEAM_TOKEN", "red-test-secret")
    monkeypatch.setenv("BAYORA_BLUE_TEAM_TOKEN", "blue-test-secret")

    response = client.get(
        "/bayora/private/red",
        headers={"Authorization": "Bearer wrong-token"},
    )

    assert response.status_code == 401


def test_missing_configuration_fails_closed(monkeypatch):
    monkeypatch.delenv("BAYORA_RED_TEAM_TOKEN", raising=False)
    monkeypatch.delenv("BAYORA_BLUE_TEAM_TOKEN", raising=False)

    response = client.get(
        "/bayora/private/red",
        headers=RED_HEADERS,
    )

    assert response.status_code == 503
