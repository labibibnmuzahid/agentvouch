#!/usr/bin/env bash
# Register an agent with GoDaddy ANS.
#   ./register.sh csr      [host]  generate keys + CSRs
#   ./register.sh register [host]  submit the registration (prints the ownership challenge)
#   ./register.sh verify   [host]  run ACME + DNS validation, poll to ACTIVE, save the identity cert
# host defaults to ANS_DOMAIN. Its keys live in certs/ (for ANS_DOMAIN) or certs/<host>/.
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
HOST="${2:-$ANS_DOMAIN}"
if [ "$HOST" = "$ANS_DOMAIN" ]; then
  CERT_DIR=certs
  ID_FILE=.ans-agent-id
else
  CERT_DIR="certs/$HOST"
  ID_FILE="$CERT_DIR/agent-id"
fi

case "$HOST" in
buyer.*)
  NAME="AgentVouch"
  DESC="Buyer-side payment agent: verifies every payee through ANS before any money moves, and vouches for other agents"
  FUNCS=(--function "vouch:Vouch for an agent:ANS,verification,trust" --function "run_scenarios:Verify-then-pay scenarios:ANS,payments,fraud")
  ;;
supplier.*)
  NAME="AgentVouch Demo Supplier"
  DESC="Demo parts supplier that signs single-use, buyer-bound quotes with its ANS identity key"
  FUNCS=(--function "issue_quote:Issue signed quote:quote,payments")
  ;;
*)
  NAME="AgentVouch"
  DESC="Buyer-side payment agent that verifies seller identity via ANS before paying"
  FUNCS=(--function "run_scenarios:Verify-then-pay scenarios:ANS,verification,payments")
  ;;
esac

case "${1:-}" in
csr)
  [ -e "$CERT_DIR/server.key" ] && { echo "$CERT_DIR/server.key exists and may back an issued ANS cert; refusing to overwrite" >&2; exit 1; }
  mkdir -p "$CERT_DIR"
  ans-cli generate-csr --host "$HOST" --org "$ORG" --version "$VERSION" --out-dir "$CERT_DIR"
  chmod 400 "$CERT_DIR"/*.key
  ;;
register)
  [ -s "$ID_FILE" ] && { echo "already registered as $(cat "$ID_FILE"); run ./register.sh verify $HOST" >&2; exit 1; }
  ans-cli register \
    --name "$NAME" --description "$DESC" \
    --host "$HOST" --version "$VERSION" \
    --identity-csr "$CERT_DIR/identity.csr" --server-csr "$CERT_DIR/server.csr" \
    --endpoint-url "https://$HOST/" \
    --endpoint-protocol A2A \
    --metadata-url "https://$HOST/.well-known/agent-card.json" \
    "${FUNCS[@]}" \
    --json | tee "$CERT_DIR/register.out.json"
  python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print(next(l['href'] for l in d['links'] if l['rel']=='self').rsplit('/',1)[1])" "$CERT_DIR/register.out.json" > "$ID_FILE"
  echo "agentId -> $(cat "$ID_FILE")   (complete the challenge, then: ./register.sh verify $HOST)"
  ;;
verify)
  AGENT_ID="$(cat "$ID_FILE")"
  ans-cli verify-acme "$AGENT_ID" || true
  ans-cli verify-dns "$AGENT_ID" || true
  for _ in $(seq 1 30); do
    STATUS="$(ans-cli status "$AGENT_ID" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["agentStatus"]["status"])')"
    echo "status: $STATUS"
    [ "$STATUS" = "ACTIVE" ] && break
    sleep 10
  done
  ans-cli get-identity-certs "$AGENT_ID" --json | python3 -c "import json,sys;c=json.load(sys.stdin)[-1];open(sys.argv[1],'w').write(c['certificatePEM'])" "$CERT_DIR/identity.crt"
  ans-cli badge "$AGENT_ID"
  ;;
*)
  echo "usage: ./register.sh {csr|register|verify} [host]" >&2; exit 1 ;;
esac
