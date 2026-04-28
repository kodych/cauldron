"""SPA-mount tests for the FastAPI surface.

The tests here don't touch Neo4j and don't need it running. They
validate routing behaviour around the React bundle mount, which the
Docker image relies on for single-container deployment.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def app_with_dist(tmp_path, monkeypatch):
    """Spin a temporary frontend/dist and reload server.py to pick it up.

    The mount is wired at import time, so changing the path requires a
    fresh import. ``monkeypatch.setenv`` + ``importlib.reload`` is the
    cleanest way to exercise the conditional code path without leaking
    state into other tests.
    """
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text(
        "<!doctype html><html><body><div id=root>spa</div></body></html>",
        encoding="utf-8",
    )
    (dist / "asset.js").write_text("console.log('asset');", encoding="utf-8")

    monkeypatch.setenv("CAULDRON_FRONTEND_DIST", str(dist))

    # Drop any cached module so the mount runs again with the new env.
    import cauldron.api.server as server
    importlib.reload(server)
    return TestClient(server.app)


@pytest.fixture()
def app_without_dist(tmp_path, monkeypatch):
    """Reload with a non-existent dist so the mount stays disabled."""
    monkeypatch.setenv("CAULDRON_FRONTEND_DIST", str(tmp_path / "missing"))
    import cauldron.api.server as server
    importlib.reload(server)
    return TestClient(server.app)


class TestSPAMount:
    def test_root_serves_index_html(self, app_with_dist):
        r = app_with_dist.get("/")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
        assert "<div id=root>spa</div>" in r.text

    def test_real_asset_served_with_correct_mime(self, app_with_dist):
        r = app_with_dist.get("/asset.js")
        assert r.status_code == 200
        assert "javascript" in r.headers["content-type"]
        assert "console.log" in r.text

    def test_deep_link_falls_back_to_index(self, app_with_dist):
        # React Router deep-link after a hard refresh.
        r = app_with_dist.get("/hosts/10.0.1.10")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
        assert "<div id=root>spa</div>" in r.text

    def test_arbitrary_unknown_path_falls_back_to_index(self, app_with_dist):
        r = app_with_dist.get("/some/long/spa/path")
        assert r.status_code == 200
        assert "<div id=root>spa</div>" in r.text

    def test_health_route_still_returns_json(self, app_with_dist):
        # The mount must not shadow API routes.
        r = app_with_dist.get("/api/v1/health")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/json")
        body = r.json()
        assert body["name"] == "Cauldron API"
        assert body["version"] == "0.1.0"

    def test_api_404_keeps_json_shape(self, app_with_dist):
        # Nonexistent /api/v1/* paths must still return JSON 404, not the
        # SPA. Otherwise the frontend can't tell an API miss from an
        # SPA route and would render its 404 view on real backend errors.
        r = app_with_dist.get("/api/v1/does-not-exist")
        assert r.status_code == 404
        assert r.headers["content-type"].startswith("application/json")


class TestSPAMountDisabled:
    def test_root_returns_404_when_dist_missing(self, app_without_dist):
        # Dev environments don't run npm build; / should be a regular
        # 404 rather than mysteriously serving stale HTML.
        r = app_without_dist.get("/")
        assert r.status_code == 404

    def test_health_endpoint_works_without_dist(self, app_without_dist):
        r = app_without_dist.get("/api/v1/health")
        assert r.status_code == 200
        assert r.json()["version"] == "0.1.0"


@pytest.fixture(autouse=True)
def _reload_server_after_each_test():
    """Restore the default mount state so other tests aren't affected.

    A previous test in this module may have reloaded ``cauldron.api.server``
    with a temporary CAULDRON_FRONTEND_DIST. Re-import without the env
    var so the rest of the suite sees the original module-level mount
    (or no mount, if there's no real frontend/dist on disk).
    """
    yield
    import os
    import cauldron.api.server as server
    # If the test set the env var, monkeypatch already removed it. Just
    # reload so the next test starts from a clean module.
    os.environ.pop("CAULDRON_FRONTEND_DIST", None)
    importlib.reload(server)
