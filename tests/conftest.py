import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

# Child processes (`python -m vibeaudit mcp` in the MCP test, CLI runs) must import this checkout too, also when
# vibeaudit is not pip-installed: pytest's `pythonpath` setting only applies to the pytest process itself.
_SRC = str(Path(__file__).parent.parent / "src")
if _SRC not in os.environ.get("PYTHONPATH", "").split(os.pathsep):
    os.environ["PYTHONPATH"] = os.pathsep.join(p for p in (_SRC, os.environ.get("PYTHONPATH", "")) if p)


@pytest.fixture(autouse=True)
def _no_user_cache(tmp_path_factory, monkeypatch):
    """Tests never read or write the real user cache, and cached answers never leak between tests."""
    from vibeaudit import llm, store  # noqa: F401 - importing llm registers its verdict cache

    monkeypatch.setenv("VIBEAUDIT_CACHE_DIR", str(tmp_path_factory.mktemp("cache")))
    monkeypatch.setattr(store, "ENABLED", False)
    for cache in store.TimedCache.instances:  # registry, OSV and LLM verdict caches
        cache.reset()
    yield
    for cache in store.TimedCache.instances:
        cache.reset()
    from vibeaudit.updater import forget_loaded_data

    forget_loaded_data()  # a test that refreshed the data files must not leave them loaded for the next one
