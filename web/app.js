const PROOFS = [["identity", "Identity (ANS)"], ["liveness", "Liveness (ANS)"], ["authorization", "Authorization"], ["possession", "Possession"], ["quote", "Quote integrity"], ["payee", "Payee (signed card)"]];

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

function ansList(a, presented) {
  const dl = el("dl", "ans");
  const row = (k, v) => { dl.append(el("dt", "", k)); const dd = el("dd"); dd.append(v); dl.append(dd); };
  row("ANS name", el("span", "mono", a.ansName));
  const link = el("a", "mono", "leaf " + a.leafIndex.toLocaleString() + " of " + a.treeSize.toLocaleString());
  if (a.badgeUrl.startsWith("https://transparency.ans.godaddy.com/")) { link.href = a.badgeUrl; link.target = "_blank"; link.rel = "noopener"; }
  row("Transparency log", link);
  row("Sealed cert", el("span", "mono", "SHA256:" + a.sealedFingerprint.slice(0, 16) + "…"));
  if (presented && presented !== a.sealedFingerprint)
    row("Presented cert", el("span", "mono bad", "SHA256:" + presented.slice(0, 16) + "…"));
  row("Trust Index", el("span", "mono", a.trustScore == null ? "not listed" : a.trustScore + " (advisory)"));
  return dl;
}

async function getJSON(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (res.status === 429) throw new Error("rate limited, try again in a few seconds");
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

async function ask(text) {
  const out = document.getElementById("ask-result"), btn = document.getElementById("ask-btn");
  btn.disabled = true;
  out.replaceChildren(el("p", "note", "Thinking…"));
  try {
    const res = await fetch("/api/ask", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }) });
    if (res.status === 429) throw new Error("rate limited, try again in a few seconds");
    if (!res.ok) throw new Error("HTTP " + res.status);
    const a = await res.json();
    const c = el("article", "card");
    c.append(el("p", "answer", a.reply));
    c.append(el("p", "note", a.engine === "gemini"
      ? "Answered by Gemini using AgentVouch's read-only verification tools. Payment decisions are made by the verification code, not the model."
      : "Rule-based reply (Gemini not configured). Payment decisions are made by the verification code."));
    out.replaceChildren(c);
  } catch (err) {
    out.replaceChildren(el("p", "reason", "Could not ask: " + err.message));
  } finally {
    btn.disabled = false;
  }
}

async function vouch(host) {
  const out = document.getElementById("vouch-result"), btn = document.getElementById("vouch-btn");
  btn.disabled = true;
  out.replaceChildren(el("p", "note", "Checking " + host + " against the ANS transparency log…"));
  try {
    const v = await getJSON("/api/vouch?host=" + encodeURIComponent(host));
    const c = el("article", "card");
    const head = el("div", "card-head");
    head.append(el("span", "id mono", v.host), el("span", "verdict " + (v.verified ? "paid" : "blocked"), v.verdict));
    c.append(head, el("p", v.verified ? "tx" : "reason", v.reason || ""));
    if (v.ans) c.append(ansList(v.ans, v.presentedFingerprint));
    c.append(el("p", "note", v.note));
    out.replaceChildren(c);
  } catch (err) {
    out.replaceChildren(el("p", "reason", "Could not vouch: " + err.message));
  } finally {
    btn.disabled = false;
  }
}

function paymentLine(s) {
  const p = s.payment || {};
  const rail = p.rail === "capital-one-nessie" ? "Capital One Nessie" : "simulated rail";
  let text = "paid $" + s.amount.toLocaleString() + " via " + rail;
  if (p.withdrawal && p.deposit) text += " · Nessie withdrawal " + p.withdrawal.slice(0, 8) + " → deposit " + p.deposit.slice(0, 8);
  else text += " · tx " + s.tx;
  if (p.payTo) text += " · to attested account " + p.payTo.slice(0, 12);
  if (p.status) text += " · " + p.status;
  return el("p", "tx", text);
}

function card(s) {
  const c = el("article", "card");
  const head = el("div", "card-head");
  head.append(el("span", "id", "[" + s.id + "]"),
    el("span", "verdict " + (s.paid ? "paid" : "blocked"), s.paid ? "PAID" : "BLOCKED"));
  c.append(head, el("p", "title", s.title.replace(/^(SUCCESS PATH|REFUSAL) - /, "")));

  const list = el("ul", "proofs");
  let failed = false;
  for (const [key, label] of PROOFS) {
    const val = s.evidence[key];
    let state = "pass", shown = val;
    if (!val) { state = failed ? "skip" : "fail"; shown = failed ? "not reached" : "FAILED"; failed = true; }
    const li = el("li", state);
    li.append(el("span", "", label), el("span", "v", shown));
    list.append(li);
  }
  c.append(list);
  if (s.evidence.ans) c.append(ansList(s.evidence.ans, s.evidence.presentedFingerprint));
  c.append(s.paid ? paymentLine(s) : el("p", "reason", s.evidence.reason + " — no money moved."));
  return c;
}

// renderAnchor shows the latest Solana anchor; true once it covers this run.
function renderAnchor(a, state, needed) {
  const box = document.getElementById("anchor");
  if (a && a.entries >= needed) {
    const p = el("p", "tx");
    p.append("Anchored on Solana devnet: entries 0–" + (a.entries - 1) + " sealed by " + a.head.slice(0, 16) + "… · ");
    if (a.explorer && a.explorer.startsWith("https://explorer.solana.com/")) {
      const link = el("a", "", "view transaction " + a.signature.slice(0, 10) + "…");
      link.href = a.explorer; link.target = "_blank"; link.rel = "noopener";
      p.append(link);
    }
    box.replaceChildren(p);
    return true;
  }
  const msg = a ? "Last Solana anchor covers entries 0–" + (a.entries - 1) + "; this run is queued for the next one." : "Not anchored on Solana yet.";
  box.replaceChildren(el("p", "note", msg + (state && state !== "idle" ? " (" + state + ")" : "")));
  return false;
}

// applyAnchors links each ledger entry to the Solana transaction that sealed it.
function applyAnchors(anchors) {
  const confirmed = (anchors || []).filter(a => a.status === "confirmed").sort((x, y) => x.entries - y.entries);
  for (const cell of document.querySelectorAll("#ledger td[data-index]")) {
    const idx = Number(cell.dataset.index);
    const a = confirmed.find(x => x.entries > idx);
    if (!a || !a.explorer || !a.explorer.startsWith("https://explorer.solana.com/")) continue;
    const link = el("a", "", a.signature.slice(0, 10) + "…");
    link.href = a.explorer; link.target = "_blank"; link.rel = "noopener";
    cell.replaceChildren(link);
  }
}

// renderAtlas reports the MongoDB Atlas replica, re-verified server-side by
// recomputing every seal out of the database.
function renderAtlas(a) {
  const box = document.getElementById("atlas");
  if (!a) { box.replaceChildren(); return; }
  if (!a.entries) {
    box.replaceChildren(el("p", "note", "MongoDB Atlas replica: " + a.state));
    return;
  }
  const p = el("p", a.intact ? "tx" : "note");
  p.textContent = "MongoDB Atlas replica (" + a.cluster + "/" + a.database + "): " +
    a.entries.toLocaleString() + " entries, " + a.decisions.toLocaleString() + " decisions, " +
    a.agents.toLocaleString() + " agents observed · " +
    (a.intact ? "every seal recomputed from the database: chain intact" : "REPLICA DOES NOT VERIFY");
  p.style.color = a.intact ? "" : "var(--bad)";
  box.replaceChildren(p);
}

let anchorPoll = 0;
async function pollAnchor(needed) {
  const mine = ++anchorPoll;
  for (let i = 0; i < 30 && mine === anchorPoll; i++) {
    await new Promise(res => setTimeout(res, 3000));
    try {
      const l = await getJSON("/api/ledger");
      if (mine !== anchorPoll) return;
      applyAnchors(l.anchors);
      renderAtlas(l.atlas);
      if (renderAnchor(l.latestAnchor, l.anchorState, needed)) return;
    } catch (_) { return; }
  }
}

async function run() {
  const btn = document.getElementById("run");
  btn.disabled = true;
  try {
    const r = await getJSON("/api/run");
    const grid = document.getElementById("scenarios");
    grid.replaceChildren(...r.scenarios.map(card));

    const asExpected = r.scenarios.filter(s => (s.expect === "pay") === s.paid).length;
    const blocked = r.scenarios.filter(s => !s.paid).length;
    document.getElementById("summary").textContent =
      `${asExpected}/${r.scenarios.length} decisions as expected · ${r.scenarios.length - blocked} paid · ${blocked} attacks blocked`;

    const body = document.getElementById("ledger");
    body.replaceChildren(...r.ledger.map((e, i) => {
      const tr = el("tr");
      const ev = el("td", e.event === "PAYMENT_SENT" ? "ev-sent" : e.event === "PAYMENT_BLOCKED" ? "ev-blocked" : "", e.event);
      const anchorCell = el("td", "mono", "pending");
      anchorCell.dataset.index = e.index;
      tr.append(el("td", "mono", String(e.index)), ev, el("td", "mono", e.time), el("td", "", e.detail), el("td", "mono", e.hash.slice(0, 12)), anchorCell);
      return tr;
    }));
    const integ = document.getElementById("integrity");
    integ.textContent = r.ledgerOK ? `Ledger integrity verified: all ${r.ledgerSize.toLocaleString()} entries chain back to the first seal.` : "Ledger integrity FAILED.";
    integ.style.color = r.ledgerOK ? "var(--ok)" : "var(--bad)";
    const needed = r.ledger.length ? r.ledger[r.ledger.length - 1].index + 1 : 0;
    if (!renderAnchor(r.anchor, r.anchorState, needed)) pollAnchor(needed);
    getJSON("/api/ledger").then(l => { applyAnchors(l.anchors); renderAtlas(l.atlas); }).catch(() => {});
  } catch (err) {
    document.getElementById("summary").textContent = "Could not run verification: " + err.message;
  } finally {
    btn.disabled = false;
  }
}

document.getElementById("run").addEventListener("click", run);
const preset = new URLSearchParams(location.search).get("vouch");
if (preset) { document.getElementById("vouch-host").value = preset; vouch(preset); }
document.getElementById("vouch-form").addEventListener("submit", e => {
  e.preventDefault();
  const host = document.getElementById("vouch-host").value.trim();
  if (host) vouch(host);
});
document.getElementById("ask-form").addEventListener("submit", e => {
  e.preventDefault();
  const text = document.getElementById("ask-text").value.trim();
  if (text) ask(text);
});
document.getElementById("ask-examples").addEventListener("click", e => {
  if (e.target.classList.contains("chip")) {
    document.getElementById("ask-text").value = e.target.textContent;
    ask(e.target.textContent);
  }
});
document.getElementById("examples").addEventListener("click", e => {
  if (e.target.classList.contains("chip")) {
    document.getElementById("vouch-host").value = e.target.textContent;
    vouch(e.target.textContent);
  }
});
run();
