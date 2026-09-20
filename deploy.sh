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
[ -f certs/dnsid.key ] && scp -q certs/dnsid.key "$HOST:/etc/agentvouch/dnsid.key"
# The public ANS agent ids, so the deployed server can publish its agent index.
python3 - <<'IDS' > /tmp/agent-ids.json
import json, pathlib
ids = {"agentvouch.us": pathlib.Path(".ans-agent-id").read_text().strip()}
for h in ("buyer.agentvouch.us", "supplier.agentvouch.us"):
    p = pathlib.Path("certs") / h / "agent-id"
    if p.exists():
        ids[h] = p.read_text().strip()
print(json.dumps(ids))
IDS
scp -q /tmp/agent-ids.json "$HOST:/etc/agentvouch/agent-ids.json"
# env_value reads one secret out of .env, tolerating CRLF and a key pasted twice.
env_value() { grep -E "^$1=" .env 2>/dev/null | head -1 | sed -E "s/^($1=)+//" | tr -d '\r\n'; }
ship_secret() {
  value="$(env_value "$1")"
  [ -n "$value" ] || return 0
  printf '%s' "$value" | ssh "$HOST" "umask 077; cat > /etc/agentvouch/$2"
}
ship_secret NESSIE_API_KEY nessie.key
[ -f certs/nessie.json ] && scp -q certs/nessie.json "$HOST:/etc/agentvouch/nessie.json"
ship_secret GEMINI_API_KEY gemini.key
ship_secret MONGODB_URI mongo.uri
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
