// The Node receiver's authorization, rule by rule. A valid signature must never be enough: only the receiver's own grant,
// and where the grant asks for one a person's approval bound to this decision, action and document, opens an action.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as U from "./uai.mjs";
import * as G from "./grants.mjs";

const D = U.signerFromSeed(Buffer.alloc(32, 7)), R = U.signerFromSeed(Buffer.alloc(32, 8)), H = U.signerFromSeed(Buffer.alloc(32, 81));
const CAP = { name: "income-screen", version: 1, requires: ["doc_type", "monthly_income_cents"], accepts: ["doc_type", "monthly_income_cents"], evidence: ["threshold-check"], max_ttl_ms: 600000 };
const tmp = () => mkdtempSync(join(tmpdir(), "uai-grants-"));

function decision({ now = Date.now(), verdict = "pass" } = {}) {
  const doc = U.commit(`loan-${Math.random()}`, { doc_type: "paystub", monthly_income_cents: 500000 });
  const body = U.requestBody(CAP.name, 1, { identity: doc.identity, digest: doc.digest, offerFields: ["doc_type", "monthly_income_cents"], requireEvidence: ["threshold-check"], maxTtlMs: 600000 });
  const terms = U.proposeTerms(CAP, body, { decider: D.agent, requester: R.agent });
  const accept = U.seal(R, "accept", { terms_digest: U.termsDigest(terms), disclosure: doc.reveal(terms.disclose) }, { to: D.agent, ttlMs: 60000, now });
  const wire = U.issueDecision(D, accept, terms, verdict, { evidence: verdict === "pass" ? { "threshold-check": { ok: true } } : {}, now });
  return { terms, wire, acceptDigest: U.envelopeDigest(accept), subject: terms.subject };
}
const grant = (extra = {}) => new G.Grant({ id: "g1", capability: CAP.name, version: 1, requester: R.agent, deciders: [D.agent], actions: ["release-funds"], disclose_max: ["doc_type", "monthly_income_cents"], ...extra });
const verifiedOf = (d, ledger) => U.verifyDecision(d.wire, { terms: d.terms, acceptDigest: d.acceptDigest, ledger, now: Date.now() });
const code = (fn) => { try { fn(); } catch (e) { return e.code ?? e.name; } return "ok"; };

function table(grants, { approvers, dir = tmp(), audit = true } = {}) {
  return new G.GrantTable(grants ?? [grant()], {
    auditPath: audit ? join(dir, "audit.jsonl") : null, store: new G.GrantStore(join(dir, "grants.db")),
    permitLedger: new G.SqliteLedger(join(dir, "permits.db")), permitLeaseMs: 30000 });
}
function guardFor(t, ledger) {
  return new U.RemoteDecisionGuard((a) => a, { actingFor: R.agent, capability: [CAP.name, 1], trust: new U.PinnedTrust([D.agent]), ledger, grants: t, action: "release-funds" });
}

test("a valid signature alone does not open the action: with no grant nothing is permitted, and the refusal is audited", () => {
  const d = decision(), dir = tmp(), t = table([], { dir });
  const ledger = new G.SqliteLedger(join(dir, "decisions.db"));
  const g = guardFor(t, ledger);
  assert.equal(code(() => g.authorize(d.wire, { terms: d.terms, acceptDigest: d.acceptDigest })), "no_grant");
  assert.equal(g.call([d.subject.identity, d.subject.digest]), false);
  assert.match(readFileSync(join(dir, "audit.jsonl"), "utf8"), /"outcome":"no_grant"/);
  assert.equal(G.verifyAudit(join(dir, "audit.jsonl")).length, 64);
});

test("a grant permits one action, once: the second attempt on the same decision is replayed", () => {
  const d = decision(), dir = tmp(), t = table(null, { dir });
  const ledger = new G.SqliteLedger(join(dir, "decisions.db"));
  const g = guardFor(t, ledger);
  g.authorize(d.wire, { terms: d.terms, acceptDigest: d.acceptDigest });
  assert.equal(g.call([d.subject.identity, d.subject.digest]), true);
  assert.equal(g.call([d.subject.identity, d.subject.digest]), false);           // one guard, one use
  g.complete();
  assert.equal(g.permit.action, "release-funds");
  const again = guardFor(table(null, { dir }), ledger);
  assert.equal(code(() => again.authorize(d.wire, { terms: d.terms, acceptDigest: d.acceptDigest })), "replayed");
});

test("the wrong action, a withdrawn grant, an expired grant, a different decider and an over-wide disclosure are each refused", () => {
  const d = decision(), v = () => verifiedOf(d, new U.Ledger());
  assert.equal(code(() => table().permit("delete-everything", v(), d.terms)), "action");
  const dir = tmp(), t = table(null, { dir });
  t.withdraw("g1");
  assert.equal(code(() => t.permit("release-funds", v(), d.terms)), "withdrawn");
  assert.equal(code(() => table([grant({ expires_at: Date.now() - 1 })]).permit("release-funds", v(), d.terms)), "grant_expired");
  const other = U.signerFromSeed(Buffer.alloc(32, 55));
  assert.equal(code(() => table([grant({ deciders: [other.agent] })]).permit("release-funds", v(), d.terms)), "decider");
  assert.equal(code(() => table([grant({ disclose_max: ["doc_type"] })]).permit("release-funds", v(), d.terms)), "disclosure");
});

test("terms that are not the terms the decision was made under are refused (a terms-digest mismatch)", () => {
  const d = decision(), v = verifiedOf(d, new U.Ledger());
  const altered = { ...d.terms, disclose: ["doc_type"] };
  assert.equal(code(() => table().permit("release-funds", v, altered)), "terms");
  assert.equal(code(() => table().permit("release-funds", v, { ...d.terms, extra: 1 })), "terms");
});

test("a decision that is not a pass permits nothing", () => {
  const d = decision({ verdict: "retry" }), v = verifiedOf(d, new U.Ledger());
  assert.equal(code(() => table().permit("release-funds", v, d.terms)), "refused");
});

test("approval: required, from a named person, never the decider or requester, bound to this decision, action and document, unexpired, genuinely signed", () => {
  const d = decision(), dir = tmp(), t = table([grant({ approvers: [H.agent] })], { dir });
  const v = () => verifiedOf(d, new U.Ledger());
  assert.equal(code(() => t.permit("release-funds", v(), d.terms)), "approval_required");
  assert.equal(code(() => t.permit("release-funds", v(), d.terms, { approval: G.approve(U.signerFromSeed(Buffer.alloc(32, 90)), v(), "release-funds") })), "approval");   // not a named approver
  assert.equal(code(() => t.permit("release-funds", v(), d.terms, { approval: { ...G.approve(H, v(), "other-action"), } })), "approval");   // another action
  const wrongDoc = decision();
  assert.equal(code(() => t.permit("release-funds", v(), d.terms, { approval: G.approve(H, verifiedOf(wrongDoc, new U.Ledger()), "release-funds") })), "approval");   // another decision
  assert.equal(code(() => t.permit("release-funds", v(), d.terms, { approval: G.approve(H, v(), "release-funds", { now: Date.now() - 10 * 60000 }) })), "approval");   // expired
  const forged = { ...G.approve(H, v(), "release-funds"), sig: "00".repeat(64) };
  assert.equal(code(() => t.permit("release-funds", v(), d.terms, { approval: forged })), "approval");
  const good = G.approve(H, v(), "release-funds");
  const permit = t.permit("release-funds", v(), d.terms, { approval: good });
  assert.equal(permit.approver, H.agent);
  permit.complete();
});

test("a party cannot approve its own action: a grant that names the requester or decider as an approver cannot even be built", () => {
  assert.throws(() => grant({ approvers: [R.agent] }), /cannot approve itself/);
  assert.throws(() => grant({ approvers: [D.agent] }), /cannot approve itself/);
});

test("abort gives the permit back so the decision can be redeemed again; complete spends it for good", () => {
  const d = decision(), dir = tmp(), ledger = new G.SqliteLedger(join(dir, "decisions.db"));
  const t1 = table(null, { dir }), g1 = guardFor(t1, ledger);
  g1.authorize(d.wire, { terms: d.terms, acceptDigest: d.acceptDigest });
  g1.call([d.subject.identity, d.subject.digest]);
  g1.abort();
  const g2 = guardFor(table(null, { dir }), ledger);
  g2.authorize(d.wire, { terms: d.terms, acceptDigest: d.acceptDigest });            // gave back: redeemable again
  g2.call([d.subject.identity, d.subject.digest]);
  g2.complete();
  assert.equal(code(() => guardFor(table(null, { dir }), ledger).authorize(d.wire, { terms: d.terms, acceptDigest: d.acceptDigest })), "replayed");
});

test("withdrawal is durable: a new table on the same store refuses, as another process would", () => {
  const dir = tmp(), a = table(null, { dir });
  a.withdraw("g1");
  const d = decision();
  assert.equal(code(() => table(null, { dir }).permit("release-funds", verifiedOf(d, new U.Ledger()), d.terms)), "withdrawn");
});

test("the audit record is a hash chain: editing or removing an entry is detected, and a damaged chain stops the receiver at start", () => {
  const dir = tmp(), t = table(null, { dir }), path = join(dir, "audit.jsonl");
  for (let i = 0; i < 3; i++) { const d = decision(); t.permit("release-funds", verifiedOf(d, new U.Ledger()), d.terms).complete(); }
  const good = readFileSync(path, "utf8"), head = G.verifyAudit(path);
  assert.equal(good.trim().split("\n").length, 3);
  writeFileSync(path, good.replace('"outcome":"permitted"', '"outcome":"refused"'));
  assert.equal(code(() => G.verifyAudit(path)), "unavailable");
  assert.equal(code(() => table(null, { dir })), "unavailable");                       // does not start on a damaged chain
  writeFileSync(path, good.split("\n").filter((_, i) => i !== 1).join("\n"));
  assert.equal(code(() => G.verifyAudit(path)), "unavailable");                        // a removed middle entry
  writeFileSync(path, good); assert.equal(G.verifyAudit(path), head);
});

test("if the audit record cannot be written nothing is permitted, and the lease on the permit is given back", () => {
  const d = decision(), dir = tmp(), t = table(null, { dir });
  writeFileSync(join(dir, "audit.jsonl.lock"), "");                                   // a lock a crashed writer left behind
  const t2 = new G.GrantTable([grant()], { auditPath: join(dir, "audit.jsonl"), store: new G.GrantStore(join(dir, "grants.db")), permitLedger: new G.SqliteLedger(join(dir, "permits.db")) });
  const origNow = Date.now; let calls = 0;
  Date.now = () => origNow() + (calls++ > 4 ? 60000 : 0);                              // let the lock wait elapse quickly
  try { assert.equal(code(() => t2.permit("release-funds", verifiedOf(d, new U.Ledger()), d.terms)), "unavailable"); } finally { Date.now = origNow; }
  assert.ok(existsSync(join(dir, "audit.jsonl.lock")));
  assert.equal(t.permits.reserve("permit:g1", `${verifiedOf(d, new U.Ledger()).envelope.id}:release-funds`, null, { leaseMs: 1000 }).key.startsWith("permit:g1"), true);   // not left held
});

test("grants files are read strictly: an unknown key, a duplicate key or a wrong shape never becomes a wider grant", () => {
  const base = (g) => JSON.stringify({ grants: [g] });
  const ok = { id: "g", capability: CAP.name, version: 1, requester: R.agent, deciders: [D.agent], actions: ["a"] };
  assert.equal(G.loadGrants(base(ok)).length, 1);
  assert.throws(() => G.loadGrants(base({ ...ok, actoins: ["x"] })));
  assert.throws(() => G.loadGrants(base({ ...ok, actions: "a" })));
  assert.throws(() => G.loadGrants('{"grants": [], "grants": []}'));
});
