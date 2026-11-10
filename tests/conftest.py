import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))


@pytest.fixture(autouse=True)
def _no_user_cache(tmp_path_factory, monkeypatch):
    """Tests never read or write the real user cache, and cached answers never leak between tests."""
    from vibeaudit import deps, store

    monkeypatch.setenv("VIBEAUDIT_CACHE_DIR", str(tmp_path_factory.mktemp("cache")))
    monkeypatch.setattr(store, "ENABLED", False)
    for cache in (deps.REGISTRY_CACHE, deps.OSV_CACHE):
        monkeypatch.setattr(cache, "_data", None)
