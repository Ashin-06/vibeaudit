"""Environment and readiness diagnostics for `vibeaudit doctor` and the MCP `doctor` tool."""
from __future__ import annotations

import datetime as dt
import importlib.metadata
import platform
import shutil
from typing import Any, Dict

from . import __version__, bundle, deps, external, feed, parse
from .rules import CATEGORIES, RULES
from .store import cache_dir


def report() -> Dict[str, Any]:
    """Return structured health and configuration status (plain JSON-serialisable dict)."""
    static = [r for r in RULES.values() if r.category != "llm-review"]
    preview = [r for r in RULES.values() if r.preview]
    severe_preview = [r for r in RULES.values() if r.preview and r.gates_in_preview]

    key = feed.public_key()
    feed_path = cache_dir() / "data" / feed.FEED
    feed_installed = feed_path.is_file()
    doc = feed.cached() if key is not None and feed_installed else None
    loaded = feed.data()

    feed_info: Dict[str, Any] = {
        "public_key": key is not None,
        "installed": feed_installed,
        "path": str(feed_path),
        "source": "signed_feed" if doc is not None else "shipped",
        "entries": {
            "slopsquatted": len(loaded.get("slopsquatted", [])),
            "model_sunsets": len(loaded.get("model_sunsets", [])),
            "prompt_injection": len(loaded.get("prompt_injection", [])),
        },
    }
    if doc is not None:
        exp = feed._when(doc["expires"])
        days_left = max(0, (exp - dt.datetime.now(dt.timezone.utc)).days)
        feed_info.update({
            "version": doc.get("version"),
            "created": doc.get("created"),
            "expires": doc.get("expires"),
            "days_remaining": days_left,
        })

    offline_osv = {}
    for eco in bundle.ECOSYSTEMS:
        age = bundle.index_age(eco)
        if age is not None:
            offline_osv[eco] = age

    scanners = {tool: shutil.which(tool) for tool in external.TOOLS}
    try:
        installed = importlib.metadata.version("vibeaudit")
    except importlib.metadata.PackageNotFoundError:
        installed = None  # running from a source tree (PYTHONPATH=src): the `vibeaudit` command is missing
    status = "warn" if (key is None or (feed_installed and doc is None) or installed != __version__) else "ok"

    return {
        "status": status,
        "version": __version__,
        "installed": installed,
        "parser": parse.mode(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "rules": {
            "total": len(RULES),
            "static": len(static),
            "categories": len({r.category for r in static}),
            "all_categories": len(CATEGORIES),
            "preview": len(preview),
            "stable": len(RULES) - len(preview),
            "severe_preview": len(severe_preview),
        },
        "ecosystems": {
            "all": list(bundle.ECOSYSTEMS),
            "registry": list(deps.REGISTRY_ECOSYSTEMS),
        },
        "threat_feed": feed_info,
        "cache_dir": str(cache_dir()),
        "offline_osv": offline_osv,
        "external_scanners": scanners,
    }


def render_text(info: Dict[str, Any]) -> str:
    """Format doctor diagnostics as plain ASCII text."""
    r = info["rules"]
    f = info["threat_feed"]
    lines = [
        f"vibeaudit {info['version']} (status: {info['status']})",
        f"  Python:     {info['python']} on {info['platform']}",
        f"  Rules:      {r['total']} total ({r['stable']} stable, {r['preview']} preview, {r['severe_preview']} severe-gating preview)",
        f"  Ecosystems: {', '.join(info['ecosystems']['all'])}",
        f"    Registry: {', '.join(info['ecosystems']['registry'])}",
        f"  Threat feed:",
        f"    Public key: {'present' if f['public_key'] else 'missing'}",
        f"    Active:     {f['source']} (slopsquatted={f['entries']['slopsquatted']}, "
        f"sunsets={f['entries']['model_sunsets']}, injection={f['entries']['prompt_injection']})",
    ]
    if info["installed"] is None:
        lines.insert(1, "  Install:    not installed, running from source (run `pip install -e .` for the `vibeaudit` command)")
    elif info["installed"] != info["version"]:
        lines.insert(1, f"  Install:    installed {info['installed']} but running {info['version']} (reinstall to match)")
    if "expires" in f:
        lines.append(f"    Signed:     {f['created']} (expires {f['expires'][:10]}, {f['days_remaining']}d remaining)")
    elif f["installed"]:
        lines.append(f"    Feed file:  present at {f['path']} but expired or invalid (run `vibeaudit update`)")
    else:
        lines.append("    Feed file:  not installed (using shipped data; run `vibeaudit update` to pull signed feed)")
    lines.append("  Parser:     " + ", ".join(f"{k}={v}" for k, v in info["parser"].items())
                 + ("" if set(info["parser"].values()) == {"tree-sitter"} else " (`pip install vibeaudit[parse]` for tree-sitter)"))
    lines.append(f"  Cache dir:  {info['cache_dir']}")
    osv = info["offline_osv"]
    lines.append(f"  Offline OSV: {', '.join(f'{k} ({v})' for k, v in osv.items()) if osv else 'none imported'}")
    sc = info["external_scanners"]
    found_tools = [f"{k}" for k, v in sc.items() if v]
    missing_tools = [k for k, v in sc.items() if not v]
    lines.append(f"  External scanners: found=[{', '.join(found_tools) or 'none'}] optional=[{', '.join(missing_tools) or 'none'}]")
    return "\n".join(lines) + "\n"
