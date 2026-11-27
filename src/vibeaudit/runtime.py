"""Phase 6 staging-only passive runtime observability middleware for FastAPI and Express.

Double-gated: refuses to initialize unless `VIBEAUDIT_RUNTIME=1` (or `true`/`staging`) is set
AND no production environment indicator (`NODE_ENV=production`, `APP_ENV=prod`, etc.) is present.
Collects route template, method, status code, duration and boolean auth presence (never raw
Authorization headers, cookies, query strings or bodies).
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path
from typing import List

PUBLIC_HINTS = re.compile(r"(?i)(?:^|/)(?:login|signin|signup|register|health|healthz|ready|live|ping|metrics|docs|openapi)")
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
PROD_VALUES = ("prod", "production")
ENV_KEYS = ("NODE_ENV", "APP_ENV", "ENVIRONMENT", "VIBEAUDIT_ENV", "FLASK_ENV")


def _check_staging_allowed() -> None:
    if os.environ.get("VIBEAUDIT_RUNTIME", "").strip().lower() not in ("1", "true", "staging"):
        raise RuntimeError("vibeaudit runtime middleware is opt-in: set VIBEAUDIT_RUNTIME=1 in staging only")
    for key in ENV_KEYS:
        val = os.environ.get(key, "").strip().lower()
        if val in PROD_VALUES:
            raise RuntimeError(f"vibeaudit runtime middleware refuses to load when {key}={val!r}")


def _sanitize(value: str, limit: int = 200) -> str:
    return CONTROL_CHARS.sub(" ", value)[:limit]


class FastAPIMiddleware:
    """ASGI staging middleware for FastAPI / Starlette (passive observation, fail-open)."""

    def __init__(self, app, log_path: str = ".vibeaudit/runtime.jsonl", slow_ms: float = 1500.0, max_entries: int = 1000):
        _check_staging_allowed()
        self.app = app
        self.log_path = Path(log_path)
        self.slow_ms = float(slow_ms)
        self.max_entries = max(1, int(max_entries))
        self._lock = threading.Lock()
        self.errors = 0

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        start = time.monotonic()
        status = 500
        method = str(scope.get("method", "GET")).upper()
        headers = scope.get("headers") or ()
        has_auth = False
        for k, v in headers:
            name = k.decode("latin1").lower()
            if name == "authorization" and v.strip():
                has_auth = True
            elif name == "cookie":
                low = v.decode("latin1").lower()
                if any(tok in low for tok in ("session", "token", "auth", "sid")):
                    has_auth = True

        async def send_wrapper(message):
            nonlocal status
            if message.get("type") == "http.response.start":
                status = int(message.get("status", 200))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = round((time.monotonic() - start) * 1000.0, 2)
            route_obj = scope.get("route")
            raw_path = getattr(route_obj, "path", None) or str(scope.get("path", "/"))
            path = _sanitize(raw_path.split("?", 1)[0])
            anomalies: List[str] = []
            if method in ("POST", "PUT", "PATCH", "DELETE") and 200 <= status < 300 and not has_auth and not PUBLIC_HINTS.search(path):
                anomalies.append("unauthenticated_mutation")
            if duration_ms > self.slow_ms:
                anomalies.append("slow_handler")
            self._record({
                "ts": round(time.time(), 3),
                "method": _sanitize(method, 16),
                "route": path,
                "status": status,
                "duration_ms": duration_ms,
                "has_auth": has_auth,
                "anomalies": anomalies,
            })

    def _record(self, entry: dict) -> None:
        try:
            with self._lock:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                existing: List[str] = []
                if self.log_path.is_file():
                    existing = self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
                lines = existing[-(self.max_entries - 1):] if self.max_entries > 1 else []
                lines.append(json.dumps(entry, separators=(",", ":")))
                self.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError:
            # Fail-open: telemetry storage issues must never disrupt staging traffic.
            self.errors += 1


def express_middleware_js() -> str:
    """Return a double-gated, fail-open Express staging middleware script (Node CommonJS)."""
    return """// vibeaudit Phase 6 staging observability middleware (opt-in, staging only)
'use strict';
const fs = require('fs');
const path = require('path');

function checkStagingAllowed() {
  const rt = String(process.env.VIBEAUDIT_RUNTIME || '').toLowerCase();
  if (!['1', 'true', 'staging'].includes(rt)) {
    throw new Error('vibeaudit runtime middleware requires VIBEAUDIT_RUNTIME=1 in staging');
  }
  for (const key of ['NODE_ENV', 'APP_ENV', 'ENVIRONMENT', 'VIBEAUDIT_ENV']) {
    const val = String(process.env[key] || '').toLowerCase();
    if (val === 'prod' || val === 'production') {
      throw new Error('vibeaudit runtime middleware refuses to run in production (' + key + ')');
    }
  }
}

function vibeauditRuntime(options) {
  checkStagingAllowed();
  const opts = Object.assign(Object.create(null), { logPath: '.vibeaudit/runtime.jsonl', slowMs: 1500 });
  if (options && typeof options === 'object') {
    if (typeof options.logPath === 'string') opts.logPath = options.logPath;
    if (typeof options.slowMs === 'number' && options.slowMs > 0) opts.slowMs = options.slowMs;
  }
  const clean = (s) => String(s || '').replace(/[\\x00-\\x1f\\x7f]/g, ' ').slice(0, 200);
  return function vibeauditObserver(req, res, next) {
    const start = Date.now();
    res.on('finish', function () {
      try {
        const ms = Date.now() - start;
        const rawRoute = (req.baseUrl || '') + (req.route && req.route.path ? req.route.path : req.path || '/');
        const route = clean(rawRoute);
        const hasAuth = Boolean(req.headers && (req.headers.authorization || /session|token|auth|sid/i.test(String(req.headers.cookie || ''))));
        const anomalies = [];
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && res.statusCode >= 200 && res.statusCode < 300 && !hasAuth && !/login|health/i.test(route)) {
          anomalies.push('unauthenticated_mutation');
        }
        if (ms > opts.slowMs) anomalies.push('slow_handler');
        const rec = JSON.stringify({ ts: Date.now() / 1000, method: clean(req.method), route, status: res.statusCode, duration_ms: ms, has_auth: hasAuth, anomalies });
        fs.mkdirSync(path.dirname(opts.logPath), { recursive: true });
        fs.appendFile(opts.logPath, rec + '\\n', function () {});
      } catch (_err) {
        // fail-open: never break staging requests
      }
    });
    next();
  };
}

module.exports = vibeauditRuntime;
"""
