"""A scanned repository's .vibeaudit.toml must not make the long-running entry points (LSP, watch, studio, MCP)
or the Python API send its code to a model provider; only `vibeaudit scan` reads the `llm` keys."""
import pytest

from vibeaudit import llm, mcp_server
from vibeaudit.config import project_options
from vibeaudit.watch import main_options

CONFIG = 'llm = "openai"\nllm-max-requests = 50\nexclude = ["vendor/**"]\n'


@pytest.fixture
def repo(tmp_path, monkeypatch):
    (tmp_path / ".vibeaudit.toml").write_text(CONFIG)
    (tmp_path / "app.py").write_text('import os\nos.system("ls " + input())\n')
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-a-real-key")
    calls = []

    def no_model(*a, **k):
        calls.append(a)
        raise AssertionError("a model provider was called because of the repository's config")

    monkeypatch.setattr(llm, "triage", no_model)
    monkeypatch.setattr(llm, "review", no_model)
    return tmp_path, calls


def test_project_options_leave_the_llm_keys_out(repo):
    root, _ = repo
    opts = project_options(str(root))
    assert opts.llm is None and opts.excludes == ["vendor/**"]  # the other settings still apply
    assert project_options(str(root), llm="openai").llm == "openai"  # an explicit caller can still turn it on


def test_watch_lsp_and_studio_options(repo):
    root, _ = repo
    assert main_options(str(root), None, [], None).llm is None


def test_mcp_scan_does_not_call_a_model(repo):
    root, calls = repo
    out = mcp_server.tool_scan_project({"path": str(root)})
    assert out["findings"] and not calls
