# AgentVouch

Agents that verify **who they're paying** — and refuse impostors. Built on
GoDaddy's **ANS** (domain-anchored identity), paying via **Capital One Nessie**,
with a tamper-evident audit ledger (Peraton: resilient financial infrastructure).

## Run
```
go run .
```
- **[A]** pays the real supplier (success path)
- **[B]–[E]** block a lookalike domain, a forged signature, a replay, and a
  swapped quote — each with on-screen **evidence** and a sealed ledger entry.

## Why it wins Best Use of ANS
Identity is the core mechanic: Discover → Resolve → **Verify** → Connect, and
"never let discovery alone authorize an action." The demo shows the success path
**and** the refusal path, shows the evidence, and names its threat model — exactly
the three things the GoDaddy deck asks for.

## Tracks & prizes
GoDaddy (Best Use of ANS) · Capital One (Nessie) · Peraton (resilient
infrastructure). MLH: GoDaddy Registry domain · MongoDB Atlas · Gemini · Vultr · Solana.
