#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-8787}"

echo "== Update @openai/codex and restart codex-mcp-bridge =="

if ! command -v npm >/dev/null 2>&1; then
  echo "npm not found" >&2
  exit 1
fi

if command -v codex >/dev/null 2>&1; then
  echo "Before: $(codex --version 2>/dev/null || true)"
else
  echo "Before: codex not found on PATH"
fi

echo "Updating @openai/codex@latest ..."
npm i -g @openai/codex@latest

if command -v codex >/dev/null 2>&1; then
  echo "After:  $(codex --version 2>/dev/null || true)"
else
  echo "After: codex not found on PATH (check PATH / install)" >&2
fi

echo "Restarting codex-mcp-bridge (to pick up new codex version) ..."
systemctl --user restart codex-mcp-bridge
sleep 2

/home/alfadb/.openclaw/workspace/tools/check_codex_mcp_bridge.sh "$PORT"
