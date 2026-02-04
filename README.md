# codex-mcp-bridge

A small, local-only HTTP daemon that wraps the `codex mcp-server` process (stdio) and provides:

- **Stable sessions** (`sessionId`) with persisted history (thread IDs are ephemeral)
- **Optional Bearer token auth**
- **Conservative security defaults** (local bind, overrides disabled unless explicitly enabled)

This repo also contains **OpenClaw integration notes** and helper scripts.

## Layout

- `skills/codex-mcp-bridge/` — OpenClaw skill entry (documentation + daemon script)
- `systemd/` — service unit files (Linux)
- `tools/` — helper scripts (health check, update codex + restart)
- `docs/` — design notes

## Quick start (foreground)

```bash
python3 skills/codex-mcp-bridge/scripts/codexd.py \
  --host 127.0.0.1 \
  --port 8787 \
  --cwd /abs/path/to/workspace \
  --store-dir /abs/path/to/state/codex-mcp-bridge \
  --token "<random-long-secret>"
```

Health:

```bash
curl -H 'Authorization: Bearer <token>' http://127.0.0.1:8787/health
```

## OpenClaw: recommended deployment model (cross-platform)

### Goal

- Gateway runs on Linux.
- A Windows/macOS/Linux **node host** (`openclaw node run`) connects to the gateway.
- Codex needs to run **on that node machine** (e.g., Windows-only toolchains/projects).

### Recommended approach (Phase 1)

- Run this daemon **on the node machine** (not on the gateway).
- Keep it bound to `127.0.0.1`.
- Have the gateway invoke node-local calls via `host=node system.run` (e.g., call `curl` against `http://127.0.0.1:8787`).

Rationale: OpenClaw node host is an execution surface (`system.run`), not a plugin runtime.

### Why not “gateway codexd -> node starts mcp-server and forwards streams”?

MCP servers are long-lived stdio processes; `system.run` is a one-shot execution API.
To do transparent forwarding you’d need a **node-side daemon** anyway (process lifecycle + bidirectional RPC).

So the simplest stable solution is: **daemon runs on the node**, gateway uses node exec to call it.

## Roadmap (unified tech stack)

We expect to evolve toward a unified TypeScript/Node implementation:

- A shared core library for session store + security policy.
- A node-side daemon for Windows/macOS/Linux.
- (Optional) a gateway plugin/service for orchestration.

See `docs/ARCHITECTURE.md`.
