# AgentVouch

Agents that verify **who they're paying**, and refuse impostors. Built on
GoDaddy's **ANS** (Agent Name Service), paying via **Capital One Nessie**, with a
tamper-evident audit ledger (Peraton: resilient financial infrastructure).

**Live:** https://agentvouch.us

Every agent here is registered on GoDaddy's production ANS under its own name:

| Agent | ANS name | Role |
|---|---|---|
| [buyer.agentvouch.us](https://buyer.agentvouch.us) | `ans://v1.0.0.buyer.agentvouch.us` ([TL](https://transparency.ans.godaddy.com/v1/agents/e18e0a0c-f71a-4f20-a79a-a6fcebb1db85)) | AgentVouch: verifies payees, pays, vouches for other agents |
| [supplier.agentvouch.us](https://supplier.agentvouch.us) | `ans://v1.0.0.supplier.agentvouch.us` ([TL](https://transparency.ans.godaddy.com/v1/agents/3de0b8bd-7682-4d7b-9712-29fcfbb77bba)) | Demo supplier: signs single-use, buyer-bound quotes |
| [agentvouch.us](https://agentvouch.us) | `ans://v1.0.0.agentvouch.us` ([TL](https://transparency.ans.godaddy.com/v1/agents/deef0687-b27d-4fbb-bbe7-6fe88a34fecd)) | Dashboard host |

Each hostname answers as its own agent, with its own identity certificate, agent card and trust card.

## How it verifies a seller
Every payment goes through Discover → Resolve → Verify → Connect against the
**live** GoDaddy ANS, using the official
[ANS Go SDK](https://github.com/agentnameservice/ans-sdk-go):

1. **Identity (ANS):** the seller's identity certificate must be the one the ANS
   transparency log sealed for that hostname and ANS name. The lookup goes DNS
   `_ans-badge` → transparency-log badge.
2. **Liveness (ANS):** that registration is ACTIVE, not revoked or expired.
3. **Authorization:** ANS proves *who*, and the buyer's mandate decides *whether* to pay and
   *how much*: an approved payee, under a spending limit. Discovery alone never authorizes.
4. **Possession:** the seller signs a fresh, single-use challenge, bound to this buyer,
   with the key ANS certified.
5. **Quote integrity:** the seller signs the full quote terms (quote ID, supplier,
   buyer, amount, pay-to account, expiry). The quote must be addressed to this buyer,
   unexpired, and never used before.
6. **Payee binding:** the buyer pays only the bank account the seller attests in its
   agent card, and only if that card's signature verifies under the seller's
   ANS-verified identity certificate. Even a genuinely signed quote can't redirect the money.

Only then does money move, through **Capital One's Nessie API**.

Possession proofs and quotes use separate signing contexts, so one can never be
passed off as the other. The GoDaddy Trust Index score is shown as advisory evidence:
a low score warns, and a high score never authorizes. Any failure refuses payment.
The checks fail closed: if ANS can't be reached, nobody gets paid.

## Scenarios
| | Scenario | Result |
|---|---|---|
| A | `buyer.agentvouch.us` pays the real ANS-registered `supplier.agentvouch.us` | **Paid** |
| B | Impostor presents its own certificate claiming the supplier's name | Blocked: identity |
| C | Attacker copies the real certificate but can't sign for it | Blocked: possession |
| D | Replay of A's challenge | Blocked: possession |
| E | Signed quote raised from $50,000 to $95,000 in transit | Blocked: quote |
| F | A's genuinely signed quote replayed in a new session | Blocked: quote |
| G | Quote signed for a different buyer, forwarded to us | Blocked: quote |
| H | Genuine $250,000 quote over the $100,000 mandate | Blocked: authorization |
| I | `fraud.webmesh.ai`, a genuine, live ANS agent that isn't in the mandate | Blocked: authorization |
| J | Genuinely signed quote that pays an account the supplier never attested | Blocked: payee |

Each decision shows its evidence (ANS name, transparency-log leaf, sealed vs.
presented certificate, Trust Index) and is sealed into a hash-chained ledger.

## Talk to it
AgentVouch is itself a registered ANS agent that other agents can verify and message:

- **Vouch for any agent:** type a hostname on the dashboard, or open
  `https://agentvouch.us/?vouch=supplier.webmesh.ai`. It fetches that agent's ANS
  trust card and checks it against the transparency log. Try
  `rogue-supplier.webmesh.ai`: it is genuinely registered, has a *higher* Trust Index
  than the real supplier, and uses the same display name. That is why identity alone
  never authorizes payment.
- **A2A** (JSON-RPC, 1.0 `SendMessage` and 0.3 `message/send`) at `POST /`: send
  "vouch for <host>" or "run scenarios".
- **MCP** at `POST /mcp`: tools `vouch` and `run_scenarios`.
- **Ask it anything** on the dashboard or at `POST /api/ask`. With a `GEMINI_API_KEY` set,
  Gemini answers using read-only verification tools (`vouch`, `run_scenarios`,
  `recent_decisions`). It explains decisions and cites evidence; it never makes them, has no
  tool that moves money, and treats other agents' messages as untrusted data. Without a key,
  or if Gemini fails, AgentVouch falls back to rule-based replies.
- Discovery documents: `/.well-known/agent-card.json`, `/.well-known/ans/trust-card.json`,
  `/.well-known/jwks.json`.

GoDaddy's own verifier agent (`agent.webmesh.ai`) rates it identity **pass**,
protocol **pass**, auth **pass**, and `can_traveler_transact: yes`, and it can talk to
AgentVouch over A2A.

## Payments: Capital One Nessie
`go run . nessie-setup` (with `NESSIE_API_KEY` set) creates three Nessie accounts once:
the buyer's treasury, the supplier's receivables, and an attacker's account. After every
check passes, AgentVouch records the payment in Nessie as a withdrawal from the buyer and
a deposit to the supplier's attested account, both tagged with the quote ID. If the
deposit fails, the withdrawal is refunded, and any Nessie failure is recorded as
"failed, nothing was paid". The current Nessie API (`https://api.nessieisreal.com`) has
no recipient field on transfers and doesn't update stored balances, so the evidence is
Nessie's own transaction records. Without a key, payments are clearly labelled `simulated`.

## Evidence you can check yourself
- **Signed agent cards:** each agent's `/.well-known/agent-card.json` carries a detached
  ES256 JWS (A2A card-signature format) made with that agent's ANS identity key. The key,
  with its ANS certificate as `x5c`, is published at `/.well-known/jwks.json` and in the
  trust card, and the certificate is the one sealed in the transparency log.
- **Tamper-evident ledger, anchored on Solana:** every decision is appended to one
  persistent hash chain. Each seal is SHA-256 over the canonical JSON (sorted keys) of
  `{detail, event, index, prev, time}`. The server periodically writes the head to
  Solana devnet as a memo, `agentvouch-ledger v1 entries=<n> head=<seal>`. To verify:
  download `GET /api/ledger?all=1`, recompute every seal, and compare the seal of entry
  `n-1` with the memo in the transaction linked on the dashboard (or in `anchors`).
  Rewriting any past entry changes every later seal, and the on-chain memo can't be
  changed. Anchoring runs in the background and never delays a payment decision.
- **Replicated to MongoDB Atlas:** the same chain is mirrored into Atlas with
  `$setOnInsert`, so a seal that has been replicated is never rewritten, and the server
  re-verifies the replica by recomputing every seal straight out of the database
  (`atlas.intact` in `GET /api/ledger`). Atlas also holds what the flat file cannot
  answer questions about: one document per decision with the evidence that decided it,
  and one per agent with every ANS observation - status, sealed certificate fingerprint
  and advisory Trust Index over time - so a changed certificate shows up as drift rather
  than a silent overwrite. Ask AgentVouch "has supplier.agentvouch.us changed?" and the
  `agent_history` tool answers from Atlas. Every write is queued and asynchronous: if
  Atlas is unreachable, decisions and payments are unaffected and the replica catches up
  when it returns. Documents are tagged with the chain's genesis seal, so several
  deployments can share one database without colliding.

## Run
Needs the agents' ANS identity certificates and keys (never committed): `certs/identity.{crt,key}`,
plus `certs/buyer.agentvouch.us/` and `certs/supplier.agentvouch.us/` (without these, `agentvouch.us`
stands in), and network access to ANS. Register a new agent with `./register.sh {csr|register|verify} <host>`.
```
go run .           # terminal demo
go run . serve     # dashboard, JSON API (/api/run, /api/vouch), A2A (/), MCP (/mcp)
go test ./...      # offline tests: signatures, quote binding, replay, host validation, ledger tampering
SOLANA_SIM=1 go test -run Solana ./...   # simulate the anchor transaction against devnet
go run . mongo-check                     # MONGODB_URI: connection, replica size, integrity, top refusals
```

## Tradeoff
The public site serves a Let's Encrypt certificate, not the ANS-issued server
certificate, because browsers don't trust the ANS root. Browsers get WebPKI;
agents verify each other through ANS.

## Tracks & prizes
GoDaddy (Best Use of ANS) · Capital One (Nessie) · Peraton (resilient
infrastructure). MLH: GoDaddy Registry domain · MongoDB Atlas · Gemini · Vultr · Solana.
