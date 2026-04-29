from __future__ import annotations

import json
from pathlib import Path

import pytest

try:
    from httpx import ASGITransport, AsyncClient
    from kcrash.api.server import app
    HAS_API_DEPS = True
except ImportError:
    HAS_API_DEPS = False


pytestmark = pytest.mark.skipif(not HAS_API_DEPS, reason="fastapi/httpx not installed")


FIXTURES_DIR = Path(__file__).parent / "fixtures"
MOCK_PATH = FIXTURES_DIR / "mock_vmcore.json"


@pytest.fixture(autouse=True)
def ensure_mock_data():
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    if not MOCK_PATH.exists():
        from scripts.mock_vmcore_info import MOCK_DATA
        with open(MOCK_PATH, "w") as f:
            json.dump(MOCK_DATA, f, indent=2, default=str)
    yield


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"


@pytest.mark.anyio
async def test_stats_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "cache" in data


@pytest.mark.anyio
async def test_clear_cache_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.delete("/cache")
        assert resp.status_code == 200
        assert resp.json()["status"] == "cache cleared"


@pytest.mark.anyio
async def test_analyze_without_llm():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "vmcore_path": str(MOCK_PATH),
            "vmlinux_path": "dummy",
        })
        assert resp.status_code == 503


@pytest.mark.anyio
async def test_crash_not_found():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/crashes/nonexistent")
        assert resp.status_code == 404
