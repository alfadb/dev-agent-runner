# Plan: Unified Dev-Agent Runner (Codex/OpenCode/Claude Code/...)

> This document captures the agreed direction from chat discussions (2026-02-04).

## Goals

- Build a **general-purpose local runner** that can control multiple developer agents/tools:
  - Codex (MCP stdio)
  - Claude Code (interactive CLI)
  - OpenCode (CLI/daemon; TBD)
  - Potentially others
- Support **cross-platform** execution (Windows/Linux/macOS), including OS-specific projects.
- Integrate with OpenClaw in two deployment modes:
  - **Gateway plugin/service** (orchestrator / convenience tooling)
  - **Node-side execution** (run on a node machine and be invoked via `system.run`)

## Non-goals (initially)

- Do **not** attempt to build a transparent MCP stream forwarder via `system.run`.
- Do **not** force all backends into a single UX; only a small common API is standardized.

## Key decision

**Unify the tech stack around Node/TypeScript**, not Go/Rust/Python, because:

- OpenClaw plugin/service ecosystem is Node/TS.
- Codex CLI and many developer tools already depend on Node.
- Cross-platform distribution is achievable (Phase 1: require Node; Phase 2: packaged binaries).

## Architecture

### Core idea

- Build a **daemon** that exposes a stable API and implements the common concerns:
  - Sessions: `sessionId` (stable), history persistence, title + search
  - Security: local-only defaults, optional token, conservative override rules
  - Process lifecycle: start/restart, health checks, logs

- Add **provider adapters** for each backend tool.

### Layering

1. **Core library (`core/`)**
   - Session store (sessionId/threadId mapping if needed)
   - Request/response schemas
   - Security policy (token, override allowlists, cwd containment)
   - Minimal auditing/logging hooks

2. **Providers (`providers/<name>/`)**
   Each provider is responsible for:
   - How to start/stop the underlying tool
   - How to send a prompt and parse output
   - Capability declaration
   - Any provider-specific payload extensions

3. **Daemon (`daemon/`)**
   - HTTP API
   - Routes requests to the selected provider
   - Enforces global security policies

4. **Integration surfaces**
   - **Node-side daemon** (runs on Windows/macOS/Linux nodes)
   - Optional **Gateway plugin service** for orchestration/convenience

## OpenClaw deployment model

### Phase 1 (selected, minimal)

- Run the daemon on the **node machine** (e.g., Windows for Windows-only projects).
- Bind it to `127.0.0.1`.
- Gateway invokes it via node execution:
  - `host=node system.run` runs a local command that calls `http://127.0.0.1:<port>`.

Rationale:
- OpenClaw node host is an exec surface (`system.run`), not a plugin runtime.
- Long-lived stdio processes require a node-side daemon anyway.

### Phase 2 (optional)

- Implement a gateway plugin/service that:
  - Selects the right node
  - Generates requests
  - Uses node exec to call the node-local daemon
  - Parses and returns results to the agent

### Phase 3 (advanced)

- If `system.run` overhead becomes a bottleneck:
  - Node daemon establishes an outbound WS connection to the gateway
  - Gateway forwards requests over that channel

## API guidelines

- Standardize only a minimal common set:
  - `GET /health`
  - `GET /sessions`
  - `POST /sessions` (create)
  - `POST /sessions/<id>/run` or `/continue`
  - `GET /sessions/<id>`
  - `GET /sessions/search?q=...`
- Allow provider-specific extensions via `providerPayload` fields.

## Security defaults

- Default bind: `127.0.0.1`
- Recommend token auth; required if bound beyond loopback
- Override knobs disabled by default:
  - `cwd` override only when explicitly enabled, and must remain within a configured base dir
  - `sandbox` and `approval_policy` overrides only when explicitly enabled and allowlisted

## Roadmap

1. Stabilize Codex provider (current Python version is the reference behavior).
2. Implement the daemon in Node/TS requiring Node installed (distribution option 1).
3. Add a second provider with a different interaction model (Claude Code recommended) to validate abstractions.
4. Optional: package binaries per OS to reduce node-side setup.
