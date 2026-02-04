# codex-mcp-bridge

Run **Codex CLI** as an **MCP server** (`codex mcp-server`) and keep a persistent session that OpenClaw (or you) can drive via a small local daemon.

This skill provides a lightweight bridge process:
- Spawns `codex mcp-server` (stdio)
- Performs MCP initialization
- Calls tools exposed by Codex MCP server:
  - `codex` (start a session) → returns `threadId` + `content`
  - `codex-reply` (continue session) → returns `threadId` + `content`
- Exposes a local HTTP API for controlling the ongoing session.

## Why
OpenClaw currently doesn't ship an MCP client, so to "control Codex via MCP" we run a dedicated MCP client daemon locally.

## Prereqs
1. Install Codex CLI:
   - `npm i -g @openai/codex`
2. Log in once (interactive):
   - `codex login --device-auth`
   - `codex login status`

## Run
### Foreground (debug)
```bash
python3 skills/codex-mcp-bridge/scripts/codexd.py \
  --port 8787 \
  --cwd /home/alfadb/.openclaw/workspace \
  --store-dir /home/alfadb/.openclaw/state/codex-mcp-bridge

# If PATH resolution fails, you MUST pin the codex executable:
# python3 skills/codex-mcp-bridge/scripts/codexd.py --codex-cmd /path/to/codex --port 8787 --cwd /home/alfadb/.openclaw/workspace --store-dir /home/alfadb/.openclaw/state/codex-mcp-bridge
```

### Foreground with auth token (recommended)
```bash
python3 skills/codex-mcp-bridge/scripts/codexd.py \
  --port 8787 \
  --cwd /home/alfadb/.openclaw/workspace \
  --token "<random-long-secret>"
```

### systemd user service (recommended)
This repo includes a ready-made unit file at:
- `workspace/systemd/codex-mcp-bridge.service`

Install it into your user systemd directory:
```bash
mkdir -p ~/.config/systemd/user
cp /home/alfadb/.openclaw/workspace/systemd/codex-mcp-bridge.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now codex-mcp-bridge
journalctl --user -u codex-mcp-bridge -f
```

Auth token via env file (recommended):
```bash
mkdir -p ~/.config/openclaw
cat > ~/.config/openclaw/codex-mcp-bridge.env <<'EOF'
CODEXD_TOKEN=<random-long-secret>

# If codex is installed under nvm/npm and not visible to systemd, set PATH here.
# Example (adjust to your setup):
# PATH=/home/alfadb/.nvm/current/bin:/usr/local/bin:/usr/bin:/bin
EOF
systemctl --user restart codex-mcp-bridge
```

## HTTP API
All responses are JSON.

- `GET /health`
  - `{ "ok": true, "pid": <int|null>, "ready": true, "authRequired": true|false }`

- `POST /start`
  - Body: `{ "prompt": "...", "title": "..."?, "model": "gpt-5.2"?, "sandbox": "workspace-write"?, "approval_policy": "untrusted"?, "cwd": "/abs/path"? }`
  - Returns: `{ "sessionId": "<bridge-managed>", "threadId": "<ephemeral>", ... }`

- `POST /continue` (recommended)
  - Body: `{ "sessionId": "...", "prompt": "..." }`
  - Returns: `{ "sessionId": "...", "threadId": "...", ... }`
  - If the underlying Codex MCP server was restarted and forgot the thread, the bridge will automatically:
    1) start a new Codex thread by injecting the saved conversation log, then
    2) retry the reply.

- `GET /sessions` (recommended)
  - Returns: `{ "sessions": [ { "sessionId": "...", "createdAtMs": ..., "updatedAtMs": ..., "title": "", "titleLocked": true|false, "titleSource": "auto|manual" }, ... ] }`

- `GET /sessions/search?q=<text>&limit=3`
  - Returns top candidates for picking the right session by title/content (best-effort heuristic).

- `GET /sessions/<sessionId>`
  - Returns: the full persisted session JSON (including history)

- `POST /sessions/rename`
  - Body: `{ "sessionId": "...", "title": "..." }`
  - Returns: `{ "ok": true }`

- `POST /sessions/autoname`
  - Body: `{ "sessionId": "...", "force": true|false? }`
  - Returns: `{ "ok": true, "title": "..." }`
  - Notes:
    - If the session was manually renamed (locked), autoname is a no-op unless `force=true`.

### Auth
If started with `--token`, all POST requests must include:
- `Authorization: Bearer <token>`

### Override knobs (disabled by default)
For safety, the daemon ignores potentially dangerous overrides unless explicitly enabled:
- `cwd` override requires `--allow-cwd-override` and must stay within `--cwd`
- `sandbox` override requires `--allow-sandbox-override` and is allowlisted
- `approval_policy` override requires `--allow-approval-override` and is allowlisted

## Notes
- This bridge is intentionally minimal. If you want streaming tokens, we'll need to implement MCP progress notifications (future).
- Default model is controlled by `~/.codex/config.toml` unless overridden per request.
- The daemon does **not** ship a hardcoded node/codex.js fallback. This is intentional: hardcoded paths tend to break after nvm/node upgrades.
