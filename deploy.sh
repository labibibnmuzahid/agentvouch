#!/usr/bin/env bash
# Build for the Vultr box and (re)deploy it behind Caddy: ./deploy.sh
set -euo pipefail
export PATH="/usr/local/go/bin:$PATH"
cd "$(dirname "$0")"
HOST="${DEPLOY_HOST:-root@64.177.45.57}"

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o bin/agentvouch .
ssh "$HOST" 'install -d -m 0700 /etc/agentvouch'
scp -q certs/identity.crt certs/identity.key "$HOST:/etc/agentvouch/"
for name in buyer supplier; do
  dir="certs/$name.agentvouch.us"
  if [ -f "$dir/identity.crt" ]; then
    scp -q "$dir/identity.crt" "$HOST:/etc/agentvouch/$name.crt"
    scp -q "$dir/identity.key" "$HOST:/etc/agentvouch/$name.key"
  fi
done
[ -f certs/solana-devnet.json ] && scp -q certs/solana-devnet.json "$HOST:/etc/agentvouch/solana.json"
NESSIE_KEY="$(grep -E '^NESSIE_API_KEY=' .env 2>/dev/null | cut -d= -f2- || true)"
[ -n "$NESSIE_KEY" ] && printf '%s' "$NESSIE_KEY" | ssh "$HOST" 'umask 077; cat > /etc/agentvouch/nessie.key'
[ -f certs/nessie.json ] && scp -q certs/nessie.json "$HOST:/etc/agentvouch/nessie.json"
GEMINI_KEY="$(grep -E '^GEMINI_API_KEY=' .env 2>/dev/null | cut -d= -f2- || true)"
[ -n "$GEMINI_KEY" ] && printf '%s' "$GEMINI_KEY" | ssh "$HOST" 'umask 077; cat > /etc/agentvouch/gemini.key'
MONGO_URI="$(grep -E '^MONGODB_URI=' .env 2>/dev/null | cut -d= -f2- || true)"
[ -n "$MONGO_URI" ] && printf '%s' "$MONGO_URI" | ssh "$HOST" 'umask 077; cat > /etc/agentvouch/mongo.uri'
true
scp -q bin/agentvouch deploy/agentvouch.service deploy/Caddyfile "$HOST:/tmp/"
ssh "$HOST" bash -s <<'REMOTE'
set -euo pipefail
chmod 0600 /etc/agentvouch/*
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
