"""Read-only security prober for live local stdio MCP servers (`vibeaudit probe --mcp-cmd`)."""
from __future__ import annotations

import hashlib
import json
import queue
import re
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .agentscan import TOOL_POISON_MARKERS
from .model import Finding
from .store import loads_json

MAX_STDOUT_BYTES = 2 * 1024 * 1024
MAX_DESCRIPTION_CHARS = 4_000
DANGEROUS_CAPABILITY = re.compile(
    r"(?i)\b(?:exec|execute_?(?:command|code|shell)|run_?(?:command|shell|bash)|shell|bash|terminal|eval"
    r"|write_?file|delete_?file|remove_?file|modify_?file|sql_?query)\b"
)
SAFETY_GUARD = re.compile(r"(?i)\b(?:allowlist|whitelist|confirm\w*|approv\w*|read[- ]?only|sandbox\w*|dry[- ]?run)\b")
SUSPICIOUS_PARAM_NAMES = frozenset({
    "sidenote", "context_dump", "conversation_history", "system_prompt",
    "credentials", "env_vars", "ssh_key", "private_key", "api_keys",
})


class McpProbeError(Exception):
    pass


def _canonical_hash(payload_text: str) -> str:
    return hashlib.sha256(payload_text.encode("utf-8", "replace")).hexdigest()


def _has_invisible_unicode(text: str) -> bool:
    for ch in text:
        cp = ord(ch)
        if (
            0x200B <= cp <= 0x200F
            or 0x202A <= cp <= 0x202E
            or 0x2060 <= cp <= 0x206F
            or cp == 0xFEFF
            or 0xE0000 <= cp <= 0xE007F
        ):
            return True
    return False


def _collect_schema_strings(obj: Any, prefix: str = "inputSchema", depth: int = 0) -> List[Tuple[str, str]]:
    """Return `(path, text)` pairs across nested schema dicts/lists (depth-bounded)."""
    out: List[Tuple[str, str]] = []
    if depth > 20:
        return out
    if isinstance(obj, str):
        out.append((prefix, obj))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj[:100]):
            out.extend(_collect_schema_strings(item, f"{prefix}[{idx}]", depth + 1))
    elif isinstance(obj, dict):
        for k, v in list(obj.items())[:100]:
            key_s = str(k)
            out.append((f"{prefix}.{key_s}", key_s))
            out.extend(_collect_schema_strings(v, f"{prefix}.{key_s}", depth + 1))
    return out


def analyse_tools(
    server_label: str,
    tools: List[Dict[str, Any]],
    pin_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """Inspect an MCP `tools/list` payload for poisoning, exfiltration traps, dangerous capabilities, and rug pulls."""
    canonical = json.dumps(tools, sort_keys=True, separators=(",", ":"))
    manifest_hash = _canonical_hash(canonical)
    findings: List[Finding] = []

    if pin_hash and pin_hash.strip().lower() != manifest_hash.lower():
        findings.append(Finding(
            "LLM027", server_label, 0,
            f"MCP tool manifest hash {manifest_hash[:12]} does not match pinned hash {pin_hash.strip().lower()[:12]} "
            "(possible rug-pull or unapproved server change).",
            "high", snippet=manifest_hash, source="mcp-probe",
        ))

    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = str(tool.get("name") or "<unnamed>")
        desc = str(tool.get("description") or "")
        texts: List[Tuple[str, str]] = [("description", desc)]
        if isinstance(tool.get("inputSchema"), dict):
            texts.extend(_collect_schema_strings(tool["inputSchema"]))

        # Inspect description and schema strings for covert instructions and stealth Unicode
        for field_path, text in texts:
            if not text:
                continue
            m = TOOL_POISON_MARKERS.search(text)
            if m:
                findings.append(Finding(
                    "LLM027", f"{server_label}#{name}", 0,
                    f"MCP tool `{name}` ({field_path}) contains covert prompt-injection instructions (`{m.group(0)[:60]}`).",
                    "critical", snippet=text.strip().splitlines()[0][:200], source="mcp-probe",
                ))
                break
            if _has_invisible_unicode(text):
                findings.append(Finding(
                    "LLM027", f"{server_label}#{name}", 0,
                    f"MCP tool `{name}` ({field_path}) contains hidden zero-width, bidi, or Unicode tag characters.",
                    "high", snippet=repr(text[:160]), source="mcp-probe",
                ))
                break

        if len(desc) > MAX_DESCRIPTION_CHARS:
            findings.append(Finding(
                "LLM027", f"{server_label}#{name}", 0,
                f"MCP tool `{name}` has an oversized description ({len(desc)} chars > {MAX_DESCRIPTION_CHARS}), "
                "which can conceal hidden instructions.",
                "medium", snippet=desc[:160], source="mcp-probe",
            ))

        props = ((tool.get("inputSchema") or {}).get("properties") or {}) if isinstance(tool.get("inputSchema"), dict) else {}
        if isinstance(props, dict):
            for prop_name in props:
                if str(prop_name).lower() in SUSPICIOUS_PARAM_NAMES:
                    findings.append(Finding(
                        "LLM027", f"{server_label}#{name}", 0,
                        f"MCP tool `{name}` declares suspicious exfiltration parameter `{prop_name}`.",
                        "high", snippet=str(prop_name), source="mcp-probe",
                    ))

        if DANGEROUS_CAPABILITY.search(f"{name} {desc}") and not SAFETY_GUARD.search(desc):
            findings.append(Finding(
                "LLM005", f"{server_label}#{name}", 0,
                f"MCP tool `{name}` exposes an unconstrained dangerous capability with no approval or allowlist guard.",
                "high", snippet=desc.strip().splitlines()[0][:200] if desc.strip() else name, source="mcp-probe",
            ))

    return {
        "server": server_label,
        "tools_count": len(tools),
        "manifest_hash": manifest_hash,
        "tools": [
            {"name": str(t.get("name", "")), "description": str(t.get("description", ""))[:160]}
            for t in tools if isinstance(t, dict)
        ],
        "findings": findings,
    }


def _reader_worker(stream: Any, out_q: "queue.Queue[Optional[str]]") -> None:
    total = 0
    try:
        while total < MAX_STDOUT_BYTES:
            line = stream.readline()
            if not line:
                break
            total += len(line)
            out_q.put(line.decode("utf-8", "replace"))
    except OSError:
        pass
    finally:
        out_q.put(None)


def _send(proc: subprocess.Popen, msg: Dict[str, Any]) -> None:
    if proc.stdin is None:
        raise McpProbeError("MCP server stdin is not open")
    proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
    proc.stdin.flush()


def _wait_response(out_q: "queue.Queue[Optional[str]]", target_id: int, deadline: float) -> Dict[str, Any]:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise McpProbeError("timed out waiting for MCP server JSON-RPC response")
        try:
            line = out_q.get(timeout=remaining)
        except queue.Empty:
            raise McpProbeError("timed out waiting for MCP server JSON-RPC response") from None
        if line is None:
            raise McpProbeError("MCP server closed stdout before replying")
        line = line.strip()
        if not line:
            continue
        try:
            msg = loads_json(line)
        except ValueError:
            continue
        if isinstance(msg, dict) and msg.get("id") == target_id:
            if "error" in msg and msg["error"] is not None:
                raise McpProbeError(f"MCP server returned error: {msg['error']}")
            return msg


def probe_stdio(
    argv: List[str],
    timeout: float = 15.0,
    pin_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """Start a local stdio MCP server, read `tools/list` safely without invoking tools, and audit its definitions."""
    if not argv or not argv[0].strip():
        raise McpProbeError("--mcp-cmd requires an executable command")
    try:
        proc = subprocess.Popen(  # noqa: S603 - explicit user-provided MCP server command, shell=False
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except OSError as exc:
        raise McpProbeError(f"cannot start MCP server `{argv[0]}`: {exc}") from None

    out_q: "queue.Queue[Optional[str]]" = queue.Queue()
    reader = threading.Thread(target=_reader_worker, args=(proc.stdout, out_q), daemon=True)
    reader.start()
    deadline = time.monotonic() + max(1.0, float(timeout))
    try:
        _send(proc, {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "vibeaudit-probe", "version": __version__},
            },
        })
        _wait_response(out_q, 1, deadline)
        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        resp = _wait_response(out_q, 2, deadline)
        result = resp.get("result")
        tools = result.get("tools", []) if isinstance(result, dict) else []
        if not isinstance(tools, list):
            tools = []
    finally:
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        try:
            proc.terminate()
            proc.wait(timeout=1.5)
        except (OSError, subprocess.SubprocessError):
            try:
                proc.kill()
            except OSError:
                pass
    return analyse_tools(" ".join(argv), tools, pin_hash=pin_hash)
