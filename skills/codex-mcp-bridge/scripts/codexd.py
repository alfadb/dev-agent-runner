#!/usr/bin/env python3
"""codexd.py

A tiny MCP client daemon that spawns `codex mcp-server` (stdio) and exposes
an HTTP API to drive a *persistent* Codex session.

- MCP protocol: newline-delimited JSON-RPC messages (stdio transport)
- Discovers two tools from Codex MCP server:
  - tools/call name="codex"
  - tools/call name="codex-reply"

HTTP API:
  GET  /health
  POST /start {prompt, model?, sandbox?, approval_policy?, cwd?}
  POST /reply {threadId, prompt}

Security notes:
- Binds to 127.0.0.1 by default (local-only).
- Optional bearer token auth via --token.
- By default, *ignores* override fields that can widen execution scope
  (cwd/sandbox/approval_policy) unless explicitly enabled via flags.

This is designed for local use only.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import signal
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, List

MCP_VERSION = "2025-11-25"

# Default maximum request body size. Enough for prompts, not for abuse.
DEFAULT_MAX_BODY_BYTES = 256 * 1024

# Conservative allowlists for dangerous override knobs.
SANDBOX_ALLOWLIST = {"workspace-write", "workspace-read", "none"}
APPROVAL_POLICY_ALLOWLIST = {"untrusted", "trusted"}


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _is_within(child: str, parent: str) -> bool:
    """Return True if realpath(child) is within realpath(parent)."""
    child_r = os.path.realpath(child)
    parent_r = os.path.realpath(parent)
    try:
        common = os.path.commonpath([child_r, parent_r])
    except Exception:
        return False
    return common == parent_r


def _now_ms() -> int:
    return int(time.time() * 1000)


def _clean_title(s: str, max_len: int = 40) -> str:
    s = " ".join((s or "").strip().split())
    s = s.replace("\n", " ").replace("\r", " ").strip()
    if len(s) > max_len:
        s = s[: max_len - 1].rstrip() + "…"
    return s


def _auto_title_from_history(history: List[dict]) -> str:
    """Heuristic title from earliest user prompt (no LLM)."""
    for h in history:
        if h.get("role") == "user":
            txt = (h.get("text") or "").strip()
            if txt:
                # Take first sentence-ish / line.
                first = txt.splitlines()[0]
                return _clean_title(first, max_len=40)
    return ""


def _extract_text(res: dict) -> str:
    """Best-effort extract plain text from Codex MCP result."""
    sc = res.get("structuredContent") or {}
    if isinstance(sc, dict) and sc.get("content"):
        return str(sc.get("content"))
    content = res.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        # MCP often uses [{type:'text', text:'...'}]
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text") or ""))
        if parts:
            return "\n".join(parts)
    return ""


class SessionStore:
    """Persist sessions using a stable, bridge-managed sessionId.

    We intentionally do NOT use threadId as the storage key because threadId is
    ephemeral across mcp-server restarts.
    """

    def __init__(self, root: str):
        self.root = root
        self.index_path = os.path.join(root, "sessions.json")
        self._lock = threading.Lock()
        os.makedirs(root, exist_ok=True)
        if not os.path.exists(self.index_path):
            self._write_index({"sessions": {}})

    def _read_index(self) -> dict:
        try:
            with open(self.index_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"sessions": {}}

    def _write_index(self, data: dict):
        tmp = self.index_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.index_path)

    def _session_path(self, session_id: str) -> str:
        return os.path.join(self.root, f"{session_id}.json")

    def new(self, meta: dict) -> str:
        session_id = uuid.uuid4().hex[:12]
        meta = dict(meta or {})
        meta["title"] = _clean_title(str(meta.get("title") or ""))
        obj = {
            "sessionId": session_id,
            "createdAtMs": _now_ms(),
            "updatedAtMs": _now_ms(),
            "meta": meta,
            "threadId": meta.get("threadId"),
            "history": [],  # list[{role,text,tsMs}]
        }
        with self._lock:
            with open(self._session_path(session_id), "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
            idx = self._read_index()
            idx.setdefault("sessions", {})[session_id] = {
                "createdAtMs": obj["createdAtMs"],
                "updatedAtMs": obj["updatedAtMs"],
                "title": meta.get("title") or "",
                "titleLocked": bool(meta.get("titleLocked")),
                "titleSource": meta.get("titleSource") or "",
            }
            self._write_index(idx)
        return session_id

    def get(self, session_id: str) -> Optional[dict]:
        path = self._session_path(session_id)
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def save(self, session: dict):
        session["updatedAtMs"] = _now_ms()
        with self._lock:
            with open(self._session_path(session["sessionId"]), "w", encoding="utf-8") as f:
                json.dump(session, f, ensure_ascii=False, indent=2)
            idx = self._read_index()
            meta = session.get("meta") or {}
            idx.setdefault("sessions", {})[session["sessionId"]] = {
                "createdAtMs": session.get("createdAtMs"),
                "updatedAtMs": session.get("updatedAtMs"),
                "title": meta.get("title") or "",
                "titleLocked": bool(meta.get("titleLocked")),
                "titleSource": meta.get("titleSource") or "",
            }
            self._write_index(idx)

    def list(self) -> List[dict]:
        idx = self._read_index().get("sessions", {})
        out = []
        for sid, meta in idx.items():
            out.append({"sessionId": sid, **meta})
        out.sort(key=lambda x: x.get("updatedAtMs") or 0, reverse=True)
        return out

    def search(self, query: str, limit: int = 3) -> List[dict]:
        q = (query or "").strip().lower()
        if not q:
            return self.list()[:limit]

        candidates = []
        for item in self.list():
            sid = item.get("sessionId")
            s = self.get(str(sid)) or {}
            meta = s.get("meta") or {}
            title = str(meta.get("title") or item.get("title") or "")
            hay = " ".join([
                title,
                " ".join((h.get("text") or "") for h in (s.get("history") or [])[-10:])
            ]).lower()

            score = 0
            if q in title.lower():
                score += 100
            if q in hay:
                score += 30
            # recency
            score += int((item.get("updatedAtMs") or 0) / 1_000_000)

            candidates.append((score, item))

        candidates.sort(key=lambda x: x[0], reverse=True)
        return [it for _, it in candidates[:limit]]

    def rename(self, session_id: str, title: str):
        session = self.get(session_id)
        if not session:
            raise KeyError("unknown sessionId")
        meta = session.setdefault("meta", {})
        meta["title"] = _clean_title(title)
        meta["titleLocked"] = True
        meta["titleSource"] = "manual"
        self.save(session)

    def autoname(self, session_id: str, *, force: bool = False, prefer_last_user: bool = True) -> str:
        """Auto-generate a title from history.

        - If titleLocked and not force: no-op
        - prefer_last_user: use most recent user message; otherwise first user message
        """
        session = self.get(session_id)
        if not session:
            raise KeyError("unknown sessionId")
        meta = session.setdefault("meta", {})
        if meta.get("titleLocked") and not force:
            return str(meta.get("title") or "")

        hist = session.get("history", [])
        title = ""
        if prefer_last_user:
            for h in reversed(hist):
                if h.get("role") == "user":
                    txt = (h.get("text") or "").strip()
                    if txt:
                        title = _clean_title(txt.splitlines()[0], max_len=40)
                        break
        if not title:
            title = _auto_title_from_history(hist)

        if title:
            meta["title"] = title
            meta["titleSource"] = "auto"
            self.save(session)
        return title

    def maybe_autoname_after_continue(self, session_id: str):
        """Autoname only when not locked and title is empty/placeholder."""
        session = self.get(session_id)
        if not session:
            raise KeyError("unknown sessionId")
        meta = session.setdefault("meta", {})
        if meta.get("titleLocked"):
            return
        title = str(meta.get("title") or "")
        # Consider placeholder if empty.
        if not title:
            self.autoname(session_id, force=False, prefer_last_user=True)
            return
        # If titleSource is auto, allow refreshing to reflect latest user prompt.
        if meta.get("titleSource") == "auto":
            self.autoname(session_id, force=False, prefer_last_user=True)

    def append(self, session_id: str, role: str, text: str):
        session = self.get(session_id)
        if not session:
            raise KeyError("unknown sessionId")
        session.setdefault("history", []).append({"role": role, "text": text, "tsMs": _now_ms()})
        self.save(session)

    def set_thread(self, session_id: str, thread_id: str):
        session = self.get(session_id)
        if not session:
            raise KeyError("unknown sessionId")
        session["threadId"] = thread_id
        session.setdefault("meta", {})["threadId"] = thread_id
        self.save(session)

    def build_injection(self, session_id: str, max_chars: int = 12000) -> str:
        session = self.get(session_id)
        if not session:
            raise KeyError("unknown sessionId")
        hist = session.get("history", [])
        # Keep the tail so we fit within max_chars.
        lines = []
        for h in hist:
            role = h.get("role")
            text = (h.get("text") or "").strip()
            if not text:
                continue
            lines.append(f"[{role}] {text}")
        blob = "\n".join(lines)
        if len(blob) > max_chars:
            blob = blob[-max_chars:]
        return (
            "We are continuing a previous Codex session. "
            "The prior MCP server was restarted, so you DO NOT have memory of it.\n"
            "Below is the conversation log (most recent at bottom).\n\n"
            + blob
            + "\n\nContinue from here."
        )


class MCPClient:
    def __init__(self, cwd: Optional[str] = None, codex_cmd: Optional[str] = None):
        self.cwd = cwd
        self.codex_cmd = codex_cmd
        self.proc: Optional[subprocess.Popen] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._next_id = 1
        self._pending: Dict[int, queue.Queue] = {}
        self.ready = False

    def start(self):
        if self.proc is not None:
            return

        # Prefer an explicit --codex-cmd, otherwise resolve `codex` from PATH.
        # No fallback: hardcoded node/codex.js paths are brittle across upgrades.
        codex_cmd = self.codex_cmd or shutil.which("codex")
        if not codex_cmd:
            raise RuntimeError(
                "`codex` not found. Install @openai/codex and ensure it's on PATH, "
                "or start codexd.py with --codex-cmd /path/to/codex"
            )
        argv = [codex_cmd, "mcp-server"]

        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.cwd,
            text=True,
            bufsize=1,
        )

        assert self.proc.stdin and self.proc.stdout and self.proc.stderr

        self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader_thread.start()

        self._stderr_thread = threading.Thread(target=self._stderr_loop, daemon=True)
        self._stderr_thread.start()

        # Initialize handshake
        _ = self.request(
            "initialize",
            {
                "protocolVersion": MCP_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "openclaw-codex-bridge", "version": "0.1.0"},
            },
            timeout=10,
        )
        # Notify initialized
        self.notify("notifications/initialized", {})

        # Verify tools exist
        tools = self.request("tools/list", {}, timeout=10)
        names = [t.get("name") for t in tools.get("tools", [])]
        if "codex" not in names or "codex-reply" not in names:
            raise RuntimeError(f"Unexpected tools from codex mcp-server: {names}")

        self.ready = True

    def stop(self, timeout: float = 10.0):
        if not self.proc:
            return
        proc = self.proc
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=timeout)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        self.proc = None
        self.ready = False

    def _stderr_loop(self):
        assert self.proc and self.proc.stderr
        for line in self.proc.stderr:
            # Keep stderr for debugging; do not treat as protocol.
            print(f"[codex-mcp stderr] {line.rstrip()}")

    def _reader_loop(self):
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception as e:
                print(f"[codex-mcp] Failed to parse line: {line[:200]} ({e})")
                continue

            msg_id = msg.get("id")
            if msg_id is None:
                # Notification from server (ignore for now)
                continue

            with self._lock:
                q = self._pending.get(int(msg_id))
            if q:
                q.put(msg)

    def _send(self, obj: dict):
        if not self.proc or not self.proc.stdin:
            raise RuntimeError("codex mcp-server not started")
        self.proc.stdin.write(_json_dumps(obj) + "\n")
        self.proc.stdin.flush()

    def notify(self, method: str, params: dict):
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def request(self, method: str, params: dict, timeout: float = 60) -> dict:
        with self._lock:
            req_id = self._next_id
            self._next_id += 1
            q: queue.Queue = queue.Queue(maxsize=1)
            self._pending[req_id] = q

        self._send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})

        try:
            msg = q.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError(f"MCP request timeout: {method}")
        finally:
            with self._lock:
                self._pending.pop(req_id, None)

        if "error" in msg:
            raise RuntimeError(msg["error"])
        return msg.get("result", {})

    def tools_call(self, name: str, arguments: dict, timeout: float = 1800) -> dict:
        return self.request("tools/call", {"name": name, "arguments": arguments}, timeout=timeout)


class APIServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address,
        RequestHandlerClass,
        mcp: MCPClient,
        default_cwd: str,
        token: str,
        allow_cwd_override: bool,
        allow_sandbox_override: bool,
        allow_approval_override: bool,
        max_body_bytes: int,
        store: SessionStore,
        max_inject_chars: int,
    ):
        super().__init__(server_address, RequestHandlerClass)
        self.mcp = mcp
        self.default_cwd = default_cwd
        self.token = token
        self.allow_cwd_override = allow_cwd_override
        self.allow_sandbox_override = allow_sandbox_override
        self.allow_approval_override = allow_approval_override
        self.max_body_bytes = max_body_bytes
        self.store = store
        self.max_inject_chars = max_inject_chars


class Handler(BaseHTTPRequestHandler):
    server: APIServer

    def _send_json(self, code: int, obj: Any):
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _require_auth(self) -> bool:
        if not self.server.token:
            return True
        auth = self.headers.get("Authorization", "")
        if auth == f"Bearer {self.server.token}":
            return True
        self._send_json(401, {"error": "unauthorized"})
        return False

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > self.server.max_body_bytes:
            self._send_json(413, {"error": "payload too large"})
            return {}
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def do_GET(self):
        if self.path == "/health":
            pid = self.server.mcp.proc.pid if self.server.mcp.proc else None
            self._send_json(
                200,
                {
                    "ok": True,
                    "pid": pid,
                    "ready": self.server.mcp.ready,
                    "authRequired": bool(self.server.token),
                },
            )
            return

        if self.path == "/sessions":
            if not self._require_auth():
                return
            self._send_json(200, {"sessions": self.server.store.list()})
            return

        if self.path.startswith("/sessions/search"):
            if not self._require_auth():
                return
            # Query string: /sessions/search?q=...&limit=3
            q = ""
            limit = 3
            try:
                from urllib.parse import urlparse, parse_qs

                u = urlparse(self.path)
                qs = parse_qs(u.query)
                q = (qs.get("q") or [""])[0]
                limit = int((qs.get("limit") or ["3"])[0])
            except Exception:
                pass
            self._send_json(200, {"sessions": self.server.store.search(q, limit=max(1, min(limit, 10)))})
            return

        if self.path.startswith("/sessions/"):
            if not self._require_auth():
                return
            session_id = self.path.split("/", 2)[2]
            s = self.server.store.get(session_id)
            if not s:
                self._send_json(404, {"error": "unknown sessionId"})
                return
            # Return metadata + current threadId + history (since local-only).
            self._send_json(200, s)
            return

        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if not self._require_auth():
            return

        if self.path == "/start":
            data = self._read_json()
            prompt = data.get("prompt")
            if not prompt:
                self._send_json(400, {"error": "missing prompt"})
                return

            # cwd: ignored by default unless override explicitly allowed AND within default_cwd.
            cwd = self.server.default_cwd
            if self.server.allow_cwd_override and data.get("cwd"):
                candidate = str(data.get("cwd"))
                if not os.path.isabs(candidate):
                    self._send_json(400, {"error": "cwd must be absolute"})
                    return
                if not _is_within(candidate, self.server.default_cwd):
                    self._send_json(400, {"error": "cwd must be within default_cwd"})
                    return
                cwd = candidate

            args: Dict[str, Any] = {"prompt": prompt, "cwd": cwd}

            # model is relatively safe to override.
            model = None
            if data.get("model"):
                model = str(data.get("model"))
                args["model"] = model

            # sandbox / approval-policy can widen permissions; disabled by default.
            if data.get("sandbox"):
                if self.server.allow_sandbox_override:
                    sb = str(data["sandbox"])
                    if sb not in SANDBOX_ALLOWLIST:
                        self._send_json(400, {"error": f"sandbox not allowed: {sb}"})
                        return
                    args["sandbox"] = sb

            if data.get("approval_policy"):
                if self.server.allow_approval_override:
                    ap = str(data["approval_policy"])
                    if ap not in APPROVAL_POLICY_ALLOWLIST:
                        self._send_json(400, {"error": f"approval_policy not allowed: {ap}"})
                        return
                    args["approval-policy"] = ap

            title = _clean_title(str(data.get("title") or ""))

            try:
                res = self.server.mcp.tools_call("codex", args, timeout=1800)
                thread_id = (res.get("structuredContent") or {}).get("threadId")
                session_id = self.server.store.new(
                    {
                        "title": title,
                        "cwd": cwd,
                        "model": model,
                        "threadId": thread_id,
                    }
                )
                self.server.store.append(session_id, "user", str(prompt))
                self.server.store.append(session_id, "assistant", _extract_text(res))
                if thread_id:
                    self.server.store.set_thread(session_id, str(thread_id))
                # Auto-name if no title provided.
                if not title:
                    self.server.store.autoname(session_id, force=False, prefer_last_user=False)

                self._send_json(200, {"sessionId": session_id, "threadId": thread_id, **res})
            except Exception as e:
                self._send_json(500, {"error": str(e)})
            return

        # Preferred: continue by stable sessionId.
        if self.path == "/continue":
            data = self._read_json()
            session_id = data.get("sessionId")
            prompt = data.get("prompt")
            if not session_id or not prompt:
                self._send_json(400, {"error": "missing sessionId or prompt"})
                return

            session = self.server.store.get(str(session_id))
            if not session:
                self._send_json(404, {"error": "unknown sessionId"})
                return

            thread_id = session.get("threadId")
            # If we have no threadId (or after restart the server forgets it), auto-resume:
            # start a new thread by injecting the stored conversation.
            try:
                if not thread_id:
                    inj = self.server.store.build_injection(str(session_id), max_chars=self.server.max_inject_chars)
                    args = {"prompt": inj, "cwd": (session.get("meta") or {}).get("cwd") or self.server.default_cwd}
                    if (session.get("meta") or {}).get("model"):
                        args["model"] = (session.get("meta") or {}).get("model")
                    res0 = self.server.mcp.tools_call("codex", args, timeout=1800)
                    new_thread = (res0.get("structuredContent") or {}).get("threadId")
                    if new_thread:
                        self.server.store.set_thread(str(session_id), str(new_thread))
                        thread_id = str(new_thread)

                # Try reply; if session missing, do one more resume and retry once.
                args1 = {"threadId": thread_id, "prompt": str(prompt)}
                res = self.server.mcp.tools_call("codex-reply", args1, timeout=1800)
            except Exception as e:
                msg = str(e)
                if "Session not found" in msg:
                    try:
                        inj = self.server.store.build_injection(str(session_id), max_chars=self.server.max_inject_chars)
                        args = {"prompt": inj, "cwd": (session.get("meta") or {}).get("cwd") or self.server.default_cwd}
                        if (session.get("meta") or {}).get("model"):
                            args["model"] = (session.get("meta") or {}).get("model")
                        res0 = self.server.mcp.tools_call("codex", args, timeout=1800)
                        new_thread = (res0.get("structuredContent") or {}).get("threadId")
                        if new_thread:
                            self.server.store.set_thread(str(session_id), str(new_thread))
                            thread_id = str(new_thread)
                        res = self.server.mcp.tools_call("codex-reply", {"threadId": thread_id, "prompt": str(prompt)}, timeout=1800)
                    except Exception as e2:
                        self._send_json(500, {"error": str(e2)})
                        return
                else:
                    self._send_json(500, {"error": msg})
                    return

            self.server.store.append(str(session_id), "user", str(prompt))
            self.server.store.append(str(session_id), "assistant", _extract_text(res))
            # Optionally refresh auto-title after continue.
            self.server.store.maybe_autoname_after_continue(str(session_id))
            self._send_json(200, {"sessionId": str(session_id), "threadId": thread_id, **res})
            return

        if self.path == "/sessions/rename":
            data = self._read_json()
            session_id = data.get("sessionId")
            title = data.get("title")
            if not session_id or title is None:
                self._send_json(400, {"error": "missing sessionId or title"})
                return
            try:
                self.server.store.rename(str(session_id), str(title))
                self._send_json(200, {"ok": True})
            except KeyError:
                self._send_json(404, {"error": "unknown sessionId"})
            return

        if self.path == "/sessions/autoname":
            data = self._read_json()
            session_id = data.get("sessionId")
            force = bool(data.get("force"))
            if not session_id:
                self._send_json(400, {"error": "missing sessionId"})
                return
            try:
                title = self.server.store.autoname(str(session_id), force=force, prefer_last_user=True)
                self._send_json(200, {"ok": True, "title": title})
            except KeyError:
                self._send_json(404, {"error": "unknown sessionId"})
            return

        self._send_json(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        # quieter
        return


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--cwd", default="/home/alfadb/.openclaw/workspace")

    # Compatibility controls
    ap.add_argument(
        "--codex-cmd",
        default="",
        help="Optional path to `codex` executable (otherwise resolved from PATH)",
    )

    # Persistence / resume controls
    ap.add_argument(
        "--store-dir",
        default="/home/alfadb/.openclaw/state/codex-mcp-bridge",
        help="Directory to persist sessions (json).",
    )
    ap.add_argument(
        "--max-inject-chars",
        type=int,
        default=12000,
        help="Max chars of conversation log injected when auto-resuming.",
    )

    # Security controls
    ap.add_argument("--token", default="", help="Optional bearer token for HTTP API")
    ap.add_argument(
        "--max-body-bytes",
        type=int,
        default=DEFAULT_MAX_BODY_BYTES,
        help="Max HTTP request body size in bytes",
    )
    ap.add_argument(
        "--allow-cwd-override",
        action="store_true",
        help="Allow request to set cwd (must stay within --cwd)",
    )
    ap.add_argument(
        "--allow-sandbox-override",
        action="store_true",
        help="Allow request to set sandbox (restricted allowlist)",
    )
    ap.add_argument(
        "--allow-approval-override",
        action="store_true",
        help="Allow request to set approval_policy (restricted allowlist)",
    )

    args = ap.parse_args()

    codex_cmd = args.codex_cmd.strip() or None

    mcp = MCPClient(cwd=args.cwd, codex_cmd=codex_cmd)
    mcp.start()

    store = SessionStore(args.store_dir)

    httpd = APIServer(
        (args.host, args.port),
        Handler,
        mcp=mcp,
        default_cwd=args.cwd,
        token=args.token,
        allow_cwd_override=args.allow_cwd_override,
        allow_sandbox_override=args.allow_sandbox_override,
        allow_approval_override=args.allow_approval_override,
        max_body_bytes=args.max_body_bytes,
        store=store,
        max_inject_chars=args.max_inject_chars,
    )

    def shutdown(signum, frame):
        # Avoid potential deadlocks by triggering HTTP shutdown in another thread.
        try:
            threading.Thread(target=httpd.shutdown, daemon=True).start()
        except Exception:
            pass
        try:
            mcp.stop(timeout=10.0)
        except Exception:
            pass

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print(f"codex-mcp-bridge listening on http://{args.host}:{args.port} (cwd={args.cwd})")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
