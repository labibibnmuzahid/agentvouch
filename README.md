# AgentVouch

Agents that verify **who they're paying**, and refuse impostors. Built on
GoDaddy's **ANS** (Agent Name Service), paying via **Capital One Nessie**, with a
tamper-evident audit ledger (Peraton: resilient financial infrastructure).

**Live:** https://agentvouch.us · registered as `ans://v1.0.0.agentvouch.us`
([transparency log entry](https://transparency.ans.godaddy.com/v1/agents/deef0687-b27d-4fbb-bbe7-6fe88a34fecd))

## How it verifies a seller
Every payment goes through Discover → Resolve → Verify → Connect against the
**live** GoDaddy ANS, using the official
[ANS Go SDK](https://github.com/agentnameservice/ans-sdk-go):

1. **Identity (ANS):** the seller's presented identity certificate must be the one the
   ANS transparency log sealed for that hostname and ANS name. The lookup goes
   DNS `_ans-badge` → transparency-log badge.
2. **Liveness (ANS):** that registration is ACTIVE, not revoked or expired.
3. **Authorization:** ANS proves *who*, and the buyer's mandate decides *whether to pay*.
   Discovery alone never authorizes.
4. **Possession:** the seller signs a fresh, single-use challenge with the key ANS certified.
5. **Quote integrity:** the amount is signed with that same key.

Any failure refuses payment. The checks fail closed: if ANS can't be reached,
nobody gets paid.

## Scenarios
| | Scenario | Result |
|---|---|---|
| A | Real ANS-registered supplier | **Paid** |
| B | Impostor presents its own certificate claiming the supplier's name | Blocked: identity |
| C | Attacker copies the real certificate but can't sign for it | Blocked: possession |
| D | Replay of A's challenge | Blocked: possession |
| E | Quote amount swapped after signing | Blocked: quote |
| F | `fraud.webmesh.ai`, a genuine, live ANS agent that isn't in the mandate | Blocked: authorization |

Each decision shows its evidence (ANS name, transparency-log leaf, sealed vs.
presented certificate fingerprint) and is sealed into a hash-chained ledger.

## Run
Needs the supplier's ANS identity certificate and key in `certs/identity.crt` and
`certs/identity.key` (never committed), plus network access to ANS.
```
go run .           # terminal demo
go run . serve     # dashboard, JSON API (/api/run), MCP (/mcp), agent card
```

## Tradeoff
The public site serves a Let's Encrypt certificate, not the ANS-issued server
certificate, because browsers don't trust the ANS root. Browsers get WebPKI;
agents verify each other through ANS.

## Tracks & prizes
GoDaddy (Best Use of ANS) · Capital One (Nessie) · Peraton (resilient
infrastructure). MLH: GoDaddy Registry domain · MongoDB Atlas · Gemini · Vultr · Solana.
