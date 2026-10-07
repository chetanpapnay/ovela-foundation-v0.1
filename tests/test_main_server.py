from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from app.main import APP_VERSION, app, create_application
from app.runtime import OvelaRuntime


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "ovela-foundation"
    assert data["version"] == APP_VERSION
    assert data["kernel"] == "active"


def test_security_headers_on_health_endpoint(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'self'" in response.headers["content-security-policy"]


def test_cors_preflight_for_vite_frontend(client: TestClient) -> None:
    response = client.options(
        "/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert (
        response.headers.get("access-control-allow-origin")
        == "http://localhost:5173"
    )
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_cors_blocks_unauthorized_origin(client: TestClient) -> None:
    response = client.options(
        "/health",
        headers={
            "Origin": "https://malicious-site.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert (
        response.headers.get("access-control-allow-origin")
        != "https://malicious-site.example.com"
    )


def test_v1_api_is_mounted(client: TestClient) -> None:
    response = client.post("/v1/payments/propose", json={})
    assert response.status_code == 401


def test_create_application_custom_runtime() -> None:
    runtime = OvelaRuntime()
    try:
        custom_app = create_application(runtime=runtime)
        custom_client = TestClient(custom_app)
        res = custom_client.get("/health")
        assert res.status_code == 200
    finally:
        runtime.close()