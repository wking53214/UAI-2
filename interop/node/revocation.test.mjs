// Node parity for the revision 2 rules: signed revocation and rotation, the leased ledger, the guard, and the checks
// the Python reference makes that this implementation used to skip. Each test changes one thing.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as U from "./uai.mjs";

const S = (n) => U.signerFromSeed(Buffer.alloc(32, n));
const AUTH = S(41), KEY = S(42), NEXT = S(43), STRANGER = S(44), DEC = S(45), REQ = S(46);
const T = 1_800_000_000_000;
const code = (fn) => { try { fn(); } catch (e) { return e.code || `internal:${e.message}`; } return "no error"; };
const stmt = (signer, subject, action, successor, effective = T, reason = "r") =>
  U.seal(signer, "revocation", { subject, action, successor, reason, effective_at: effective }, { now: T });

test("a subject and a listed authority may revoke, nobody else", () => {
  const st = new U.RevocationStore();
  st.accept(stmt(KEY, KEY.agent, "revoke", ""), { now: T });
  st.accept(stmt(AUTH, NEXT.agent, "revoke", ""), { authorities: [AUTH.agent], now: T });
  assert.equal(code(() => st.accept(stmt(STRANGER, DEC.agent, "revoke", ""), { authorities: [AUTH.agent], now: T })), "untrusted");
  assert.equal(code(() => st.accept(stmt(AUTH, DEC.agent, "revoke", ""), { authorities: [], now: T })), "untrusted");
  assert.ok(st.isRevoked(KEY.agent, T) && st.isRevoked(NEXT.agent, T) && !st.isRevoked(DEC.agent, T));
});

test("malformed and tampered statements are refused", () => {
  const st = new U.RevocationStore();
  const good = stmt(KEY, KEY.agent, "revoke", "");
  assert.equal(code(() => st.accept({ ...good, body: { ...good.body, reason: "edited" } }, { now: T })), "signature");
  assert.equal(code(() => st.accept(stmt(KEY, KEY.agent, "delete", ""), { now: T })), "malformed");
  assert.equal(code(() => st.accept(stmt(KEY, "nope", "revoke", ""), { now: T })), "malformed");
  assert.equal(code(() => st.accept(stmt(KEY, KEY.agent, "revoke", NEXT.agent), { now: T })), "malformed");
  assert.equal(code(() => st.accept(U.seal(KEY, "revocation", { subject: KEY.agent, action: "revoke", successor: "", reason: "r" }, { now: T }), { now: T })), "malformed");
  assert.equal(code(() => st.accept(stmt(AUTH, KEY.agent, "rotate", NEXT.agent), { authorities: [AUTH.agent], now: T })), "untrusted");
  assert.equal(code(() => st.accept(stmt(KEY, KEY.agent, "rotate", KEY.agent), { now: T })), "malformed");
  assert.ok(!st.isRevoked(KEY.agent, T + 1));
});

test("a revocation binds from its effective time", () => {
  const st = new U.RevocationStore();
  st.accept(stmt(KEY, KEY.agent, "revoke", "", T + 10_000), { now: T });
  assert.ok(!st.isRevoked(KEY.agent, T + 9_999) && st.isRevoked(KEY.agent, T + 10_000));
});

test("trust refuses a revoked pinned identity, and a stale or never-refreshed list when bounded", () => {
  const st = new U.RevocationStore();
  st.accept(stmt(KEY, KEY.agent, "revoke", ""), { now: T });
  const trust = new U.PinnedTrust([KEY.agent, NEXT.agent], [], { revocations: st });
  assert.equal(code(() => trust.admit(KEY.agent, { now: T })), "untrusted");
  assert.equal(trust.admit(NEXT.agent, { now: T }).via, "pinned");
  const bounded = new U.PinnedTrust([NEXT.agent], [], { revocations: st, maxStalenessMs: 60_000 });
  assert.equal(code(() => bounded.admit(NEXT.agent, { now: T })), "unavailable");
  st.markFresh(T);
  assert.equal(bounded.admit(NEXT.agent, { now: T + 59_000 }).via, "pinned");
  assert.equal(code(() => bounded.admit(NEXT.agent, { now: T + 61_000 })), "unavailable");
});

test("rotation is off by default, needs a pinned predecessor, and an authority's revoke withdraws the successor", () => {
  const st = new U.RevocationStore();
  st.accept(stmt(KEY, KEY.agent, "rotate", NEXT.agent), { now: T });
  assert.equal(st.predecessorOf(NEXT.agent), KEY.agent);
  assert.equal(code(() => new U.PinnedTrust([KEY.agent], [], { revocations: st }).admit(NEXT.agent, { now: T + 1 })), "untrusted");
  const follows = new U.PinnedTrust([KEY.agent], [], { revocations: st, followRotation: true });
  assert.equal(follows.admit(NEXT.agent, { now: T + 1 }).via, "rotated");
  assert.equal(code(() => follows.admit(KEY.agent, { now: T + 1 })), "untrusted");
  assert.equal(code(() => new U.PinnedTrust([STRANGER.agent], [], { revocations: st, followRotation: true }).admit(NEXT.agent, { now: T + 1 })), "untrusted");
  st.accept(stmt(AUTH, KEY.agent, "revoke", ""), { authorities: [AUTH.agent], now: T + 2 });
  assert.equal(st.predecessorOf(NEXT.agent), null);
  assert.equal(code(() => follows.admit(NEXT.agent, { now: T + 3 })), "untrusted");
});

test("the ledger: leases exclude, commit is permanent, release returns it, a lapsed lease can be taken", () => {
  const L = new U.Ledger(), exp = Date.now() + 60_000;
  const r = L.reserve("s", "m", exp, { leaseMs: 30_000 });
  assert.equal(code(() => L.reserve("s", "m", exp, { leaseMs: 30_000 })), "replayed");
  assert.equal(code(() => L.spend("s", "m", exp)), "replayed");
  L.commit(r);
  assert.equal(code(() => L.spend("s", "m", exp)), "replayed");
  const r2 = L.reserve("s", "n", exp, { leaseMs: 30_000 }); L.release(r2); L.commit(L.reserve("s", "n", exp, { leaseMs: 30_000 }));
  const t = Date.now(), old = L.reserve("s", "p", t + 600_000, { leaseMs: 1_000, now: t });
  const fresh = L.reserve("s", "p", t + 600_000, { leaseMs: 30_000, now: t + 2_000 });
  assert.equal(code(() => L.commit(old, { now: t + 2_500 })), "lease_lost");
  assert.equal(code(() => L.release(old, { now: t + 2_500 })), "lease_lost");
  L.commit(fresh, { now: t + 3_000 });
  assert.equal(code(() => L.reserve("s", "q", null, { leaseMs: 0 })), "internal:leaseMs is a positive integer, at most 3600000");
});

test("the ledger forgets expired messages, so it does not grow without bound, but never ahead of a lagging verifier", () => {
  const L = new U.Ledger({ keepMs: 0 }), wall = Date.now();
  for (let i = 0; i < 500; i++) L.spend("s", `old${i}`, wall - 10_000, { now: wall });
  L.spend("s", "trigger", wall + 60_000, { now: wall });
  assert.ok(L.seen.size <= 2, `kept ${L.seen.size}`);
  const behind = wall - 500_000;
  L.spend("s", "victim", wall - 300_000, { now: behind });
  L.spend("s", "other", wall + 60_000, { now: behind });
  assert.equal(code(() => L.spend("s", "victim", wall - 300_000, { now: behind })), "replayed");
});

// A complete exchange's terms and decision, built with the module's own functions.
function exchange(extra = {}) {
  const doc = U.commit("loan-1", { monthly_income_cents: 500000, doc_type: "paystub" });
  const cap = { name: "income-screen", version: 1, summary: "s", accepts: ["doc_type", "monthly_income_cents"], requires: ["monthly_income_cents"], evidence: ["threshold-check"], max_ttl_ms: 300000 };
  const reqBody = U.requestBody("income-screen", 1, { identity: doc.identity, digest: doc.digest, offerFields: ["doc_type", "monthly_income_cents"], requireEvidence: ["threshold-check"], maxTtlMs: 600000 });
  const terms = U.proposeTerms(cap, reqBody, { decider: DEC.agent, requester: REQ.agent });
  const request = U.seal(REQ, "request", reqBody, { to: DEC.agent, ttlMs: 60000, now: T });
  const offer = U.seal(DEC, "offer", { terms }, { to: REQ.agent, replyTo: request, ttlMs: 60000, now: T });
  const accept = U.seal(REQ, "accept", { terms_digest: U.termsDigest(terms), disclosure: doc.reveal(terms.disclose) }, { to: DEC.agent, replyTo: offer, ttlMs: 60000, now: T });
  const decision = U.issueDecision(DEC, accept, terms, "pass", { evidence: { "threshold-check": { ok: 1 } }, now: T, ...extra });
  return { doc, terms, accept, decision, acceptDigest: U.envelopeDigest(accept) };
}
const mkGuard = (ex, over = {}) => new U.RemoteDecisionGuard((a) => a, {
  actingFor: REQ.agent, capability: ["income-screen", 1], trust: new U.PinnedTrust([DEC.agent]), ledger: new U.Ledger(), clock: () => T + 1000, ...over });

test("verifyDecision refuses terms that are not complete terms", () => {
  const ex = exchange();
  const partial = { ...ex.terms }; delete partial.disclose;
  assert.equal(code(() => U.verifyDecision(ex.decision, { terms: partial, acceptDigest: ex.acceptDigest, ledger: new U.Ledger(), now: T + 1000 })), "terms");
  assert.equal(code(() => U.verifyDecision(ex.decision, { terms: { ...ex.terms, extra: 1 }, acceptDigest: ex.acceptDigest, ledger: new U.Ledger(), now: T + 1000 })), "terms");
});

test("the guard opens once, on the judged document, for its own capability and requester", () => {
  const ex = exchange(), g = mkGuard(ex);
  g.authorize(ex.decision, { terms: ex.terms, acceptDigest: ex.acceptDigest });
  assert.equal(g.call(["loan-1", "other"]), false);
  assert.equal(g.call([ex.terms.subject.identity, ex.terms.subject.digest]), true);
  assert.equal(g.call([ex.terms.subject.identity, ex.terms.subject.digest]), false);
  assert.equal(code(() => mkGuard(ex, { capability: ["other", 1] }).authorize(ex.decision, { terms: ex.terms, acceptDigest: ex.acceptDigest })), "terms");
  assert.equal(code(() => mkGuard(ex, { capability: ["income-screen", 2] }).authorize(ex.decision, { terms: ex.terms, acceptDigest: ex.acceptDigest })), "terms");
  assert.equal(code(() => mkGuard(ex, { actingFor: STRANGER.agent }).authorize(ex.decision, { terms: ex.terms, acceptDigest: ex.acceptDigest })), "audience");
  assert.equal(code(() => mkGuard(ex, { trust: new U.PinnedTrust([STRANGER.agent]) }).authorize(ex.decision, { terms: ex.terms, acceptDigest: ex.acceptDigest })), "untrusted");
});

test("the guard: a decision is accepted once per ledger, and a revocation after authorize closes it", () => {
  const ex = exchange(), ledger = new U.Ledger();
  mkGuard(ex, { ledger }).authorize(ex.decision, { terms: ex.terms, acceptDigest: ex.acceptDigest });
  assert.equal(code(() => mkGuard(ex, { ledger }).authorize(ex.decision, { terms: ex.terms, acceptDigest: ex.acceptDigest })), "replayed");
  const st = new U.RevocationStore(), g = mkGuard(ex, { trust: new U.PinnedTrust([DEC.agent], [], { revocations: st }) });
  g.authorize(ex.decision, { terms: ex.terms, acceptDigest: ex.acceptDigest });
  st.accept(stmt(DEC, DEC.agent, "revoke", ""), { now: T + 500 });
  assert.equal(g.call([ex.terms.subject.identity, ex.terms.subject.digest]), false);
});

test("a leased decision survives a crash: the lease lapses, a retry redeems, the key dedupes the action", () => {
  const ex = exchange(); let t = T + 1000; const ledger = new U.Ledger();
  const mk = () => mkGuard(ex, { ledger, clock: () => t });
  const first = mk();
  first.authorize(ex.decision, { terms: ex.terms, acceptDigest: ex.acceptDigest, leaseMs: 10_000 });
  assert.equal(first.call([ex.terms.subject.identity, ex.terms.subject.digest]), true);      // then it crashes
  assert.equal(code(() => mk().authorize(ex.decision, { terms: ex.terms, acceptDigest: ex.acceptDigest, leaseMs: 10_000 })), "replayed");
  t += 10_001;
  const retry = mk();
  retry.authorize(ex.decision, { terms: ex.terms, acceptDigest: ex.acceptDigest, leaseMs: 10_000 });
  assert.equal(retry.idempotencyKey, first.idempotencyKey);
  assert.equal(retry.call([ex.terms.subject.identity, ex.terms.subject.digest]), true);
  retry.complete();
  assert.equal(code(() => mk().authorize(ex.decision, { terms: ex.terms, acceptDigest: ex.acceptDigest, leaseMs: 10_000 })), "replayed");
});

test("a ledger that throws anything but a refusal is unavailable, never an escape or a yes", () => {
  const ex = exchange();
  const broken = { spend() { throw new Error("disk gone"); }, reserve() { throw new TypeError("net down"); } };
  assert.equal(code(() => mkGuard(ex, { ledger: broken }).authorize(ex.decision, { terms: ex.terms, acceptDigest: ex.acceptDigest })), "unavailable");
  assert.equal(code(() => mkGuard(ex, { ledger: broken }).authorize(ex.decision, { terms: ex.terms, acceptDigest: ex.acceptDigest, leaseMs: 5000 })), "unavailable");
});

test("boundedNodes refuses by length before walking, with the same count as the Python reference", () => {
  assert.equal(U.boundedNodes({ a: [1, 2, { b: null }] }, 100), 8);                   // python: bounded_nodes({"a": [1, 2, {"b": None}]}, 100) == 8
  assert.equal(U.boundedNodes({ a: new Array(300).fill(1) }, 1_000_000), 303);
  assert.equal(code(() => U.boundedNodes({ a: new Array(300).fill(1) }, 302)), "profile");
  const huge = { a: new Array(2_000_000).fill(1) };
  const t = process.hrtime.bigint();
  assert.equal(code(() => U.boundedNodes(huge, 1000)), "profile");
  assert.ok(Number(process.hrtime.bigint() - t) / 1e6 < 50, "the refusal must not walk the list");
  const wire = { ...U.seal(S(1), "request", { a: 1 }, { to: S(2).agent, ttlMs: 60000 }) };
  const big = U.seal(S(1), "request", { a: new Array(500).fill(1) }, { to: S(2).agent, ttlMs: 60000 });
  assert.equal(code(() => U.openEnvelope(big, { maxNodes: 100 })), "profile");        // refused before the signature check
  assert.ok(U.openEnvelope(wire, { maxNodes: 100 }));
});
