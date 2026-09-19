#!/usr/bin/env bash
# Step 1: register one real agent with ANS.
#   ./register.sh csr      generate keys + CSRs into ./certs
#   ./register.sh register submit registration, print the DNS TXT records to place
#   ./register.sh verify   run ACME validation, then poll status until ACTIVE
# Credentials come from .env (gitignored): ANS_API_KEY=key:secret, ANS_DOMAIN=your.domain
set -euo pipefail

export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
cd "$(dirname "$0")"
[ -f .env ] && set -a && . ./.env && set +a

: "${ANS_API_KEY:?set ANS_API_KEY=key:secret in .env}"
: "${ANS_DOMAIN:?set ANS_DOMAIN=your.domain in .env}"
export ANS_BASE_URL="${ANS_BASE_URL:-https://api.godaddy.com}"

VERSION="${ANS_VERSION:-1.0.0}"
ORG="${ANS_ORG:-AgentVouch}"
ID_FILE=.ans-agent-id

case "${1:-}" in
csr)
  ans-cli generate-csr --host "$ANS_DOMAIN" --org "$ORG" --version "$VERSION" --out-dir ./certs
  ;;
register)
  ans-cli register \
    --name "AgentVouch" \
    --description "Buyer-side payment agent that verifies seller identity via ANS before paying" \
    --host "$ANS_DOMAIN" --version "$VERSION" \
    --identity-csr ./certs/identity.csr --server-csr ./certs/server.csr \
    --endpoint-url "https://$ANS_DOMAIN/mcp" \
    --endpoint-protocol MCP \
    --metadata-url "https://$ANS_DOMAIN/.well-known/agent-card.json" \
    --function "run_scenarios:Verify-then-pay scenarios:ANS,verification,payments" \
    --json | tee register.out.json
  python3 -c "import json;print(json.load(open('register.out.json'))['agentId'])" > "$ID_FILE"
  echo "agentId -> $(cat "$ID_FILE")   (place the DNS TXT records above, then: ./register.sh verify)"
  ;;
verify)
  AGENT_ID="$(cat "$ID_FILE")"
  ans-cli verify-dns "$AGENT_ID" || true
  ans-cli verify-acme "$AGENT_ID"
  for _ in $(seq 1 30); do
    STATUS="$(ans-cli status "$AGENT_ID" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["lifecycle"]["status"])')"
    echo "status: $STATUS"
    [ "$STATUS" = "ACTIVE" ] && break
    sleep 10
  done
  ans-cli get-identity-certs "$AGENT_ID"
  ans-cli badge "$AGENT_ID"
  ;;
*)
  echo "usage: ./register.sh {csr|register|verify}" >&2; exit 1 ;;
esac
