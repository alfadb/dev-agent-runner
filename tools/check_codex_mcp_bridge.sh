#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-8787}"
URL="http://127.0.0.1:${PORT}"

say() { printf "%s\n" "$*"; }

say "== codex-mcp-bridge quick check =="

say "[1/4] codex + node versions"
if command -v codex >/dev/null 2>&1; then
  say "- codex: $(command -v codex)"
  (codex --version 2>/dev/null || true) | sed 's/^/  /'
else
  say "- codex: NOT FOUND in current shell PATH"
fi

if command -v node >/dev/null 2>&1; then
  say "- node:  $(command -v node)"
  (node -v 2>/dev/null || true) | sed 's/^/  /'
else
  say "- node: NOT FOUND in current shell PATH"
fi

say ""
say "[2/4] systemd user service status"
if command -v systemctl >/dev/null 2>&1; then
  systemctl --user status codex-mcp-bridge --no-pager -l || true
else
  say "- systemctl not available"
fi

say ""
say "[3/4] /health"
if command -v curl >/dev/null 2>&1; then
  curl -fsS "${URL}/health" | sed 's/^/  /' || {
    say "  (failed to fetch ${URL}/health)"
    exit 2
  }
else
  say "- curl not available"
fi

say ""
say "[4/4] recent logs (last 30 lines)"
if command -v journalctl >/dev/null 2>&1; then
  journalctl --user -u codex-mcp-bridge -n 30 --no-pager -l | sed 's/^/  /' || true
else
  say "- journalctl not available"
fi

say ""
say "OK"
