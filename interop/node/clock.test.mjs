// The trusted clock and the per-decision sync in the Node receiver (RACE-02 I-06, I-07a), without a database: the
// database side is stubbed here; interop against a real PostgreSQL server runs in cns_interop/tests (pytest).
import { test } from "node:test";
import assert from "node:assert/strict";
import * as U from "./uai.mjs";
import * as P from "./pg.mjs";

const D = U.signerFromSeed(Buffer.alloc(32, 7)), R = U.signerFromSeed(Buffer.alloc(32, 8));
const CAP = { name: "income-screen", version: 1, requires: ["doc_type", "monthly_income_cents"], accepts: ["doc_type", "monthly_income_cents"], evidence: ["threshold-check"], max_ttl_ms: 600000 };

function decision(now = Date.now()) {
  const doc = U.commit(`loan-${Math.random()}`, { doc_type: "paystub", monthly_income_cents: 500000 });
  const body = U.requestBody(CAP.name, 1, { identity: doc.identity, digest: doc.digest, offerFields: ["doc_type", "monthly_income_cents"], requireEvidence: ["threshold-check"], maxTtlMs: 600000 });
  const terms = U.proposeTerms(CAP, body, { decider: D.agent, requester: R.agent });
  const accept = U.seal(R, "accept", { terms_digest: U.termsDigest(terms), disclosure: doc.reveal(terms.disclose) }, { to: D.agent, ttlMs: 60000, now });
  const wire = U.issueDecision(D, accept, terms, "pass", { evidence: { "threshold-check": { ok: true } }, now });
  return { terms, wire, acceptDigest: U.envelopeDigest(accept) };
}
const code = (fn) => { try { fn(); } catch (e) { return e.code ?? e.name; } return "ok"; };
// A stand-in for PgGuard._measure: the database answers `server`; the host's wall clock is `wall`.
const guardAt = (server, wall = Date.now) => ({ _measure(max, clock) { const t = clock(); const skew = t - server(); if (Math.abs(skew) > max) throw new U.Refused("clock_skew", `skew ${skew}`); return [skew, server()]; } });

test("a trusted clock answers the database's time carried on the monotonic clock, not the host's wall clock", () => {
  const dbAhead = () => Date.now() + 3000;
  const c = new P.TrustedClock(guardAt(dbAhead), 5000, { keepMs: 120000 });
  assert.equal(code(() => c.now()), "RangeError");                       // not before sync
  c.sync();
  assert.ok(Math.abs(c.now() - dbAhead()) < 100);
  const f = c.asClock();
  assert.ok(Math.abs(f() - dbAhead()) < 100 && typeof f.sync === "function");
});

test("the tolerance must be strictly below the ledger's retention window", () => {
  assert.equal(code(() => new P.TrustedClock(guardAt(Date.now), 120000, { keepMs: 120000 })), "RangeError");
  assert.equal(code(() => new P.TrustedClock(guardAt(Date.now), 120001, { keepMs: 120000 })), "RangeError");
  assert.equal(code(() => new P.TrustedClock(guardAt(Date.now), -1, { keepMs: 120000 })), "RangeError");
  assert.equal(code(() => new P.TrustedClock(guardAt(Date.now), 119999, { keepMs: 120000 })), "ok");
});

test("sync refuses beyond the tolerance and the guard re-syncs for every decision, spending nothing when it refuses", () => {
  let offset = 0;
  const c = new P.TrustedClock(guardAt(() => Date.now() + offset), 5000, { keepMs: 120000 });
  c.sync();                                                               // start-up: agreed
  const ledger = new U.Ledger();
  const d = decision();
  const guard = new U.RemoteDecisionGuard((a) => a, { actingFor: R.agent, capability: [CAP.name, 1], trust: new U.PinnedTrust([D.agent]), ledger, clock: c.asClock() });
  offset = 3600000;                                                       // the database drifts an hour after start-up
  assert.equal(code(() => guard.authorize(d.wire, { terms: d.terms, acceptDigest: d.acceptDigest })), "clock_skew");
  assert.equal(ledger.seen.size, 0);                                      // nothing was verified or spent
  offset = 0;
  assert.equal(guard.authorize(d.wire, { terms: d.terms, acceptDigest: d.acceptDigest }).allowed, true);
});

test("a plain clock function without sync is used as before", () => {
  const ledger = new U.Ledger(), d = decision();
  const guard = new U.RemoteDecisionGuard((a) => a, { actingFor: R.agent, capability: [CAP.name, 1], trust: new U.PinnedTrust([D.agent]), ledger, clock: Date.now });
  assert.equal(guard.authorize(d.wire, { terms: d.terms, acceptDigest: d.acceptDigest }).allowed, true);
});

// RACE-02 I-07b (R2-C-04): the database's answer to the time query is read as an integer or refused as 'unavailable'; it is
// never NaN, never a float, never a passing check. (cns_interop/tests/test_clock_fail_closed.py runs the same answers through
// act.mjs against a real server.)
test("the database's time is read only when it is a plausible integer in ms", () => {
  assert.equal(P.serverTimeOf([["1793000000000"]]), 1793000000000);
  assert.equal(P.serverTimeOf([["946684800000"]]), 946684800000);
  for (const bad of [[], [[]], [[""]], [["NaN"]], [["-5"]], [["abc"]], [["1e3"]], [["1.5"]], [["Infinity"]], [["0"]], [["+1793000000000"]], [[" 1793000000000"]],
    [["0x10"]], [["946684799999"]], [["9007199254740992"]], [["12345678901234567890"]], [["1793000000000", "2"]], [["1793000000000"], ["2"]], [[null]], [[1793000000000]]]) {
    assert.equal(code(() => P.serverTimeOf(bad)), "unavailable", JSON.stringify(bad));
  }
});

test("a measurement whose database time is unreadable refuses 'unavailable' and never passes as agreement", () => {
  for (const answer of ["NaN", "abc", "-5", "Infinity"]) {
    const g = Object.create(P.PgGuard.prototype);
    g._run = () => [[answer]];
    assert.equal(code(() => g.checkClock(5000)), "unavailable", answer);
  }
  const g = Object.create(P.PgGuard.prototype);
  g._run = () => [];
  assert.equal(code(() => g.checkClock(5000)), "unavailable");
});
