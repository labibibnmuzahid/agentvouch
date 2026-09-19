#!/usr/bin/env bash
# Build for the Vultr box and (re)deploy it behind Caddy: ./deploy.sh
set -euo pipefail
export PATH="/usr/local/go/bin:$PATH"
cd "$(dirname "$0")"
HOST="${DEPLOY_HOST:-root@64.177.45.57}"

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o bin/agentvouch .
scp -q bin/agentvouch deploy/agentvouch.service deploy/Caddyfile "$HOST:/tmp/"
ssh "$HOST" bash -s <<'REMOTE'
set -euo pipefail
command -v caddy >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq caddy; }
install -m 0755 /tmp/agentvouch /usr/local/bin/agentvouch
install -m 0644 /tmp/agentvouch.service /etc/systemd/system/agentvouch.service
install -m 0644 /tmp/Caddyfile /etc/caddy/Caddyfile
systemctl daemon-reload
systemctl enable -q agentvouch caddy
systemctl restart agentvouch
systemctl reload-or-restart caddy
systemctl is-active agentvouch caddy
REMOTE
