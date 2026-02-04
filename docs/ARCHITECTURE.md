# Architecture

## Context

We want a Codex MCP bridge that works in these deployments:

- **Linux Gateway** hosts OpenClaw and receives messages.
- **Remote nodes** (Windows/macOS/Linux) connect via `openclaw node run`.
- Some projects are **OS-specific** (e.g., Windows toolchains), so Codex must run on that OS.

## Constraints

- The OpenClaw **node host is not a plugin runtime**; it mainly exposes `system.run` / `system.which`.
- MCP servers (like `codex mcp-server`) are typically long-lived stdio processes.
- We must keep a tight security posture: local-only by default, explicit auth, and conservative override rules.

## Phase 1 (selected)

### Node-local daemon

Run `codexd` on the node machine:

- Bind: `127.0.0.1`
- Auth: optional Bearer token (`--token`)
- Persistence: `--store-dir`

### Gateway → node → localhost

Gateway triggers node execution (`host=node`) to call the local daemon via HTTP.

Example (conceptual):

```bash
curl -H 'Authorization: Bearer $TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"prompt":"..."}' \
  http://127.0.0.1:8787/start
```

This avoids opening any inbound Windows ports.

## Phase 2 (unified TypeScript)

Implement a TS/Node daemon that replaces the Python `codexd.py`:

- Shared core: session store, request validation, security allowlists
- Node daemon: process lifecycle + HTTP API
- Optional gateway plugin service: orchestration + convenience tooling

## Phase 3 (optional advanced transport)

If we need lower latency or fewer `system.run` invocations:

- Node daemon maintains an outbound WS connection to the gateway.
- Gateway forwards Codex requests over that channel.

This is more complex (custom protocol + reconnect + backpressure), and should only be built if Phase 1 becomes a bottleneck.
