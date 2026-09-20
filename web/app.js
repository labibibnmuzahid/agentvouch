const PROOFS = [["identity", "Identity (ANS)"], ["liveness", "Liveness (ANS)"], ["authorization", "Authorization"], ["possession", "Possession"], ["quote", "Quote integrity"], ["payee", "Payee (signed card)"]];
const CHECK_ORDER = ["identity", "liveness", "quote", "expiry", "audience", "authorization", "payee"];

const $ = id => document.getElementById(id);

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

// copyable turns any value into a click-to-copy control, because the evidence
// worth checking is exactly the part that is tedious to retype.
function copyable(text, cls, shown) {
  const b = el("button", "copy " + (cls || ""), shown === undefined ? text : shown);
  b.type = "button";
  b.title = "Copy " + text;
  b.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text);
      const was = b.textContent;
      b.textContent = "copied";
      b.classList.add("done");
      setTimeout(() => { b.textContent = was; b.classList.remove("done"); }, 900);
    } catch (_) { toast("Clipboard blocked by the browser"); }
  });
  return b;
}

function toast(message) {
  const t = el("div", "toast", message);
  $("toasts").append(t);
  setTimeout(() => t.remove(), 5000);
}

function link(href, text, prefix) {
  if (!href || !href.startsWith(prefix)) return el("span", "mono", text);
  const a = el("a", "mono", text);
  a.href = href; a.target = "_blank"; a.rel = "noopener";
  return a;
}

// working shows staged progress with an elapsed clock. Verification talks to
// DNS, a transparency log, a bank and a model, so silence would read as a hang.
function working(host, stages) {
  const box = el("div", "working");
  const bars = el("div", "bars");
  bars.append(el("i"), el("i"), el("i"), el("i"));
  const label = el("span", "", stages[0]);
  const clock = el("span", "elapsed", "0.0s");
  box.append(bars, label, clock);
  const started = performance.now();
  let stage = 0;
  const timer = setInterval(() => {
    const secs = (performance.now() - started) / 1000;
    clock.textContent = secs.toFixed(1) + "s";
    const next = Math.min(stages.length - 1, Math.floor(secs / 1.6));
    if (next !== stage) { stage = next; label.textContent = stages[stage]; }
  }, 100);
  box.stop = () => clearInterval(timer);
  host.replaceChildren(box);
  return box;
}

function ansList(a, presented) {
  const dl = el("dl", "ans");
  const row = (k, v) => { dl.append(el("dt", "", k)); const dd = el("dd"); dd.append(v); dl.append(dd); };
  row("ANS name", copyable(a.ansName, "mono"));
  row("Transparency log", link(a.badgeUrl, "leaf " + a.leafIndex.toLocaleString() + " of " + a.treeSize.toLocaleString(), "https://transparency.ans.godaddy.com/"));
  row("Sealed cert", copyable(a.sealedFingerprint, "mono", "SHA256:" + a.sealedFingerprint.slice(0, 16) + "…"));
  if (presented && presented !== a.sealedFingerprint)
    row("Presented cert", copyable(presented, "mono bad", "SHA256:" + presented.slice(0, 16) + "…"));
  row("Trust Index", trustCell(a));
  return dl;
}

// trustCell shows the score with the registry's own reasons: the pillar vector
// and every penalty it applied. The score is advisory and never authorizes, so
// the reasons matter more than the number.
function trustCell(a) {
  const wrap = el("span");
  if (a.trustScore == null && !a.trust) {
    wrap.append(el("span", "mono", "not listed"));
    return wrap;
  }
  const t = a.trust;
  wrap.append(el("span", "mono", (t ? t.score : a.trustScore) + " (advisory)"));
  if (!t) return wrap;
  const pillars = Object.entries(t.pillars || {});
  if (pillars.length) {
    wrap.append(el("span", "note", " · " + pillars.map(([k, v]) => k + " " + v).join(", ")));
  }
  for (const p of t.penalties || []) {
    const line = el("div", "penalty");
    line.append(el("span", "mono", "−" + p.points), " " + p.signal + ": " + p.outcome.replace(/_/g, " ") + " (" + p.tier + ")");
    wrap.append(line);
  }
  if (t.base) wrap.append(el("div", "note", "base " + t.base + ", after penalties " + t.score));
  return wrap;
}

async function getJSON(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (res.status === 429) throw new Error("rate limited, try again in a few seconds");
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

async function postJSON(url, body) {
  const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (res.status === 429) throw new Error("rate limited, try again in a few seconds");
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

/* ---- ask ---------------------------------------------------------------- */

async function ask(text) {
  const out = $("ask-result"), btn = $("ask-btn");
  btn.disabled = true;
  const w = working(out, ["Reading the question…", "Resolving agents through ANS…", "Reading the audit ledger…", "Writing the answer…"]);
  try {
    const a = await postJSON("/api/ask", { text });
    w.stop();
    const c = el("article", "card");
    c.append(el("p", "answer", a.reply));
    c.append(el("p", "note", a.engine === "gemini"
      ? "Answered by Gemini through AgentVouch's read-only verification tools. Payment decisions are made by the verification code, not the model."
      : "Rule-based reply (the model was unavailable). Payment decisions are made by the verification code either way."));
    out.replaceChildren(c);
  } catch (err) {
    w.stop();
    out.replaceChildren(el("p", "reason", "Could not ask: " + err.message));
    toast("Ask failed: " + err.message);
  } finally {
    btn.disabled = false;
  }
}

/* ---- vouch -------------------------------------------------------------- */

async function vouch(host) {
  const out = $("vouch-result"), btn = $("vouch-btn");
  btn.disabled = true;
  const w = working(out, ["Looking up " + host + "…", "Reading its ANS trust card…", "Checking the transparency log…"]);
  try {
    const v = await getJSON("/api/vouch?host=" + encodeURIComponent(host));
    w.stop();
    const c = el("article", "card " + (v.verified ? "paid" : "blocked"));
    const head = el("div", "card-head");
    head.append(copyable(v.host, "id mono"), el("span", "verdict " + (v.verified ? "paid" : "blocked"), v.verdict));
    c.append(head, el("p", v.verified ? "tx" : "reason", v.reason || ""));
    if (v.ans) c.append(ansList(v.ans, v.presentedFingerprint));
    c.append(el("p", "note", v.note));
    out.replaceChildren(c);
  } catch (err) {
    w.stop();
    out.replaceChildren(el("p", "reason", "Could not vouch: " + err.message));
    toast("Vouch failed: " + err.message);
  } finally {
    btn.disabled = false;
  }
}

/* ---- quote playground --------------------------------------------------- */

let held = null;

function showTerms(q, edited) {
  const t = q.terms;
  const dl = el("dl", "terms");
  const row = (k, v, cls) => { dl.append(el("dt", "", k)); const dd = el("dd", cls); dd.append(v); dl.append(dd); };
  row("Quote", copyable(t.quoteId, "mono"));
  row("Supplier", el("span", "", t.supplier));
  row("Buyer", el("span", "", t.buyer));
  row("Amount", el("span", "", "$" + t.amountUsd.toLocaleString()), edited ? "edited" : "");
  row("Pay to", copyable(t.payTo, "mono", t.payTo.slice(0, 12) + "…"));
  row("Signature", copyable(q.signature, "mono", q.signature.slice(0, 18) + "…"));
  const box = $("q-terms");
  box.replaceChildren(dl, el("p", edited
    ? "reason" : "note", edited
    ? "One digit of the amount was changed after signing. The signature still covers the original terms."
    : "Signed with the supplier's ANS identity key, single use, expires shortly."));
}

async function issueQuote() {
  const btn = $("q-issue");
  btn.disabled = true;
  const w = working($("q-terms"), ["Asking the supplier…", "Signing with its ANS key…"]);
  try {
    const r = await postJSON("/api/quote/issue", { amountUsd: Number($("q-amount").value) || 2500 });
    w.stop();
    if (r.error) throw new Error(r.error);
    held = { quote: r.quote, edited: false };
    showTerms(r.quote, false);
    $("q-verify").disabled = false;
    $("q-tamper").disabled = false;
    $("q-checks").replaceChildren(el("p", "note", "Quote in hand. Verify it, or tamper with it first and see what the buyer does."));
  } catch (err) {
    w.stop();
    $("q-terms").replaceChildren(el("p", "reason", "Could not get a quote: " + err.message));
    toast("Quote failed: " + err.message);
  } finally {
    btn.disabled = false;
  }
}

function tamperQuote() {
  if (!held) return;
  held.quote.terms.amountUsd = held.quote.terms.amountUsd + 96500;
  held.edited = true;
  showTerms(held.quote, true);
  $("q-checks").replaceChildren(el("p", "note", "Amount raised after signing. Now verify it."));
}

async function verifyQuote() {
  if (!held) return;
  const btn = $("q-verify");
  btn.disabled = true;
  const w = working($("q-checks"), ["Resolving the signer through ANS…", "Checking the signature over the terms…", "Checking mandate and attested payee…"]);
  try {
    const r = await postJSON("/api/quote/verify", { quote: held.quote });
    w.stop();
    if (r.error) throw new Error(r.error);
    const wrap = el("div", "body");
    const head = el("div", "card-head");
    const paid = r.verdict === "WOULD PAY";
    head.append(el("span", "id mono", r.quoteId || ""), el("span", "verdict " + (paid ? "paid" : "blocked"), r.verdict || "—"));
    wrap.append(head);
    const list = el("ul", "checks");
    for (const name of CHECK_ORDER) {
      const v = (r.checks || {})[name];
      if (!v) continue;
      const failed = v.startsWith("FAIL");
      const li = el("li", failed ? "fail" : "pass");
      li.append(el("span", "mark", failed ? "✕" : "✓"), el("span", "name", name), el("span", "why", v.replace(/^(PASS|FAIL): /, "")));
      list.append(li);
    }
    wrap.append(list);
    wrap.append(el("p", "note", r.ifPaid || r.note || ""));
    $("q-checks").replaceChildren(wrap);
  } catch (err) {
    w.stop();
    $("q-checks").replaceChildren(el("p", "reason", "Could not verify: " + err.message));
    toast("Verify failed: " + err.message);
  } finally {
    btn.disabled = false;
  }
}

/* ---- decisions ---------------------------------------------------------- */

function paymentLine(s) {
  const p = s.payment || {};
  const rail = p.rail === "capital-one-nessie" ? "Capital One Nessie" : "simulated rail";
  const line = el("p", "tx");
  line.append("paid $" + s.amount.toLocaleString() + " via " + rail + " · ");
  if (p.withdrawal && p.deposit) {
    line.append("withdrawal ", copyable(p.withdrawal, "mono", p.withdrawal.slice(0, 8)), " → deposit ", copyable(p.deposit, "mono", p.deposit.slice(0, 8)));
  } else {
    line.append("tx " + s.tx);
  }
  if (p.payTo) line.append(" · to attested account " + p.payTo.slice(0, 12));
  if (p.status) line.append(" · " + p.status);
  return line;
}

function card(s, i) {
  const c = el("article", "card " + (s.paid ? "paid" : "blocked"));
  c.style.animationDelay = Math.min(i * 40, 400) + "ms";
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

/* ---- stats -------------------------------------------------------------- */

function setStat(id, value, sub, tone) {
  const dd = $(id);
  dd.replaceChildren(document.createTextNode(value));
  if (sub) dd.append(el("small", "", sub));
  dd.parentElement.classList.toggle("is-ok", tone === "ok");
  dd.parentElement.classList.toggle("is-bad", tone === "bad");
}

/* ---- ledger ------------------------------------------------------------- */

let ledgerRows = [];

function renderLedger(filter) {
  const body = $("ledger");
  const rows = ledgerRows.filter(r => filter === "all" || r.event === filter);
  body.replaceChildren(...rows.map(e => {
    const tr = el("tr");
    const cls = e.event === "PAYMENT_SENT" ? "ev-sent" : e.event === "PAYMENT_BLOCKED" ? "ev-blocked" : "ev-failed";
    const anchorCell = el("td", "mono", "pending");
    anchorCell.dataset.index = e.index;
    const seal = el("td", "mono");
    seal.append(copyable(e.hash, "mono", e.hash.slice(0, 12)));
    tr.append(el("td", "mono", String(e.index)), el("td", cls, e.event), el("td", "mono", e.time), el("td", "", e.detail), seal, anchorCell);
    return tr;
  }));
  if (!rows.length) {
    const tr = el("tr");
    const td = el("td", "note", "No entries of this kind in the last run.");
    td.colSpan = 6;
    tr.append(td);
    body.replaceChildren(tr);
  }
}

function renderAnchor(a, state, needed) {
  const box = $("anchor");
  if (a && a.entries >= needed) {
    const p = el("p", "tx");
    p.append("Anchored on Solana devnet: entries 0–" + (a.entries - 1) + " sealed by " + a.head.slice(0, 16) + "… · ");
    p.append(link(a.explorer, "view transaction " + a.signature.slice(0, 10) + "…", "https://explorer.solana.com/"));
    box.replaceChildren(p);
    setStat("s-anchor", "confirmed", "covers " + a.entries.toLocaleString() + " entries", "ok");
    return true;
  }
  const msg = a ? "Last Solana anchor covers entries 0–" + (a.entries - 1) + "; this run is queued for the next one." : "Not anchored on Solana yet.";
  box.replaceChildren(el("p", "note", msg + (state && state !== "idle" ? " (" + state + ")" : "")));
  setStat("s-anchor", a ? "pending" : "waiting", a ? "next anchor in ≤20s" : state || "");
  return false;
}

function applyAnchors(anchors) {
  const confirmed = (anchors || []).filter(a => a.status === "confirmed").sort((x, y) => x.entries - y.entries);
  for (const cell of document.querySelectorAll("#ledger td[data-index]")) {
    const idx = Number(cell.dataset.index);
    const a = confirmed.find(x => x.entries > idx);
    if (!a) continue;
    cell.replaceChildren(link(a.explorer, a.signature.slice(0, 10) + "…", "https://explorer.solana.com/"));
  }
}

function renderAtlas(a) {
  const box = $("atlas");
  if (!a) { box.replaceChildren(); return; }
  if (!a.entries) {
    box.replaceChildren(el("p", "note", "MongoDB Atlas replica: " + a.state));
    setStat("s-atlas", "offline", a.state.slice(0, 28), "bad");
    return;
  }
  const p = el("p", a.intact ? "tx" : "reason");
  p.textContent = "MongoDB Atlas replica (" + a.cluster + "/" + a.database + "): " +
    a.entries.toLocaleString() + " entries, " + a.decisions.toLocaleString() + " decisions, " +
    a.agents.toLocaleString() + " agents observed · " +
    (a.intact ? "every seal recomputed from the database: chain intact" : "REPLICA DOES NOT VERIFY");
  box.replaceChildren(p);
  setStat("s-atlas", a.entries.toLocaleString(), a.intact ? "re-verified from the database" : "does not verify", a.intact ? "ok" : "bad");
}

function renderRail(l) {
  const rail = $("rail");
  const badge = (label, live) => {
    const b = el("span", "badge " + (live ? "live" : "off"));
    b.append(el("span", "dot"), el("span", "", label));
    return b;
  };
  rail.replaceChildren(
    badge("GoDaddy ANS", true),
    badge("Capital One Nessie", true),
    badge("Solana devnet", !!l.latestAnchor),
    badge("MongoDB Atlas", !!(l.atlas && l.atlas.entries)),
    badge("Gemini", true));
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
      renderRail(l);
      if (renderAnchor(l.latestAnchor, l.anchorState, needed)) return;
    } catch (_) { return; }
  }
}

/* ---- run ---------------------------------------------------------------- */

async function run() {
  const btn = $("run");
  btn.disabled = true;
  $("summary").textContent = "Verifying every seller against the live transparency log…";
  const grid = $("scenarios");
  if (!grid.children.length) grid.replaceChildren(...Array.from({ length: 6 }, () => el("div", "skeleton")));
  try {
    const r = await getJSON("/api/run");
    grid.replaceChildren(...r.scenarios.map(card));

    const asExpected = r.scenarios.filter(s => (s.expect === "pay") === s.paid).length;
    const blocked = r.scenarios.filter(s => !s.paid).length;
    const clean = asExpected === r.scenarios.length;
    $("summary").textContent = `${asExpected}/${r.scenarios.length} decisions as expected · ${r.scenarios.length - blocked} paid · ${blocked} attacks blocked`;
    setStat("s-decisions", asExpected + "/" + r.scenarios.length, clean ? "as expected" : "unexpected result", clean ? "ok" : "bad");
    setStat("s-blocked", String(blocked), "attacks refused", "ok");
    setStat("s-ledger", r.ledgerSize.toLocaleString(), r.ledgerOK ? "chain intact" : "chain FAILED", r.ledgerOK ? "ok" : "bad");

    ledgerRows = r.ledger;
    const active = document.querySelector("#ledger-filter .chip[aria-pressed='true']");
    renderLedger(active ? active.dataset.filter : "all");

    const integ = $("integrity");
    integ.textContent = r.ledgerOK
      ? `Ledger integrity verified: all ${r.ledgerSize.toLocaleString()} entries chain back to the first seal.`
      : "Ledger integrity FAILED.";
    integ.className = "integrity " + (r.ledgerOK ? "ok" : "bad");

    const needed = r.ledger.length ? r.ledger[r.ledger.length - 1].index + 1 : 0;
    if (!renderAnchor(r.anchor, r.anchorState, needed)) pollAnchor(needed);
    getJSON("/api/ledger").then(l => { applyAnchors(l.anchors); renderAtlas(l.atlas); renderRail(l); }).catch(() => {});
  } catch (err) {
    grid.replaceChildren();
    $("summary").textContent = "Could not run verification: " + err.message;
    toast("Run failed: " + err.message);
  } finally {
    btn.disabled = false;
  }
}

/* ---- wiring ------------------------------------------------------------- */

$("frame-host").textContent = location.host;

const THEME_KEY = "agentvouch-theme";
try {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved) document.documentElement.dataset.theme = saved;
} catch (_) { /* private browsing */ }
$("theme").addEventListener("click", () => {
  const root = document.documentElement;
  const dark = root.dataset.theme
    ? root.dataset.theme === "dark"
    : window.matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem(THEME_KEY, root.dataset.theme); } catch (_) { /* ignore */ }
});

$("run").addEventListener("click", run);
$("q-issue").addEventListener("click", issueQuote);
$("q-verify").addEventListener("click", verifyQuote);
$("q-tamper").addEventListener("click", tamperQuote);

$("vouch-form").addEventListener("submit", e => {
  e.preventDefault();
  const host = $("vouch-host").value.trim();
  if (host) vouch(host);
});
$("ask-form").addEventListener("submit", e => {
  e.preventDefault();
  const text = $("ask-text").value.trim();
  if (text) ask(text);
});
$("ask-examples").addEventListener("click", e => {
  if (!e.target.classList.contains("chip")) return;
  $("ask-text").value = e.target.textContent;
  ask(e.target.textContent);
});
$("examples").addEventListener("click", e => {
  if (!e.target.classList.contains("chip")) return;
  $("vouch-host").value = e.target.textContent;
  vouch(e.target.textContent);
});
$("ledger-filter").addEventListener("click", e => {
  if (!e.target.classList.contains("chip")) return;
  for (const c of $("ledger-filter").children) c.setAttribute("aria-pressed", String(c === e.target));
  renderLedger(e.target.dataset.filter);
  getJSON("/api/ledger").then(l => applyAnchors(l.anchors)).catch(() => {});
});

// "/" focuses the hostname box, the way a search field behaves elsewhere.
document.addEventListener("keydown", e => {
  if (e.key !== "/" || /^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName)) return;
  e.preventDefault();
  $("vouch-host").focus();
});

const preset = new URLSearchParams(location.search).get("vouch");
if (preset) { $("vouch-host").value = preset; vouch(preset); }
run();
