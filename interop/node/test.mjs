// The Node implementation against the answer keys the Python reference publishes, and against itself.
// Run: node --test interop/node/test.mjs   (pytest runs it too: cns_interop/tests/test_two_systems.py)

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as U from "./uai.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const load = (p) => U.strictParse(readFileSync(root + p, "utf8"));
const V = load("contracts/uai-vectors.json");
const seed = (name) => Buffer.from(V.seeds[name].seed, "hex");

const inProfile = (v) => { try { U.checkProfile(v); return true; } catch { return false; } };

test("canonical digest: every in-profile vector matches, every out-of-profile vector is refused", () => {
  // The digest vectors file itself holds floats and a 2**64 integer, which this reader refuses by design.
  // Re-read it leniently to compare, and require that whatever this implementation cannot carry it refuses.
  const lenient = JSON.parse(readFileSync(root + "contracts/digest-vectors.json", "utf8"));
  const raw = readFileSync(root + "contracts/digest-vectors.json", "utf8");
  assert.throws(() => U.strictParse(raw), (e) => e.code === "profile");
  let matched = 0, refused = 0;
  for (const v of lenient.vectors) {
    const text = JSON.stringify(v.content);
    let content;
    try { content = U.strictParse(`{"c":${rawContent(raw, v.name)}}`).c; } catch (e) { assert.equal(e.code, "profile", v.name); refused++; continue; }
    assert.ok(inProfile(content), v.name);
    assert.equal(U.digest(content), v.digest, `${v.name}: ${text}`);
    matched++;
  }
  assert.ok(matched >= 10, `only ${matched} vectors matched`);
  assert.ok(refused >= 1, "expected the float and big-integer vectors to be refused");
});

// The original text of one vector's content, so floats and big integers reach the strict reader unaltered.
function rawContent(raw, name) {
  const at = raw.indexOf(`"name": ${JSON.stringify(name)}`);
  const c = raw.indexOf(`"content":`, at) + `"content":`.length;
  let depth = 0, i = c, inStr = false;
  for (; i < raw.length; i++) {
    const ch = raw[i];
    if (inStr) { if (ch === "\\") i++; else if (ch === "\"") inStr = false; continue; }
    if (ch === "\"") inStr = true;
    else if (ch === "{" || ch === "[") depth++;
    else if (ch === "}" || ch === "]") { depth--; if (depth === 0) return raw.slice(c, i + 1); }
  }
  throw new Error("vector content not found");
}

test("identities from the same seeds", () => {
  for (const name of Object.keys(V.seeds)) assert.equal(U.signerFromSeed(seed(name)).agent, V.seeds[name].agent);
});

test("every published envelope verifies here, and re-signing it here reproduces the signature byte for byte", () => {
  for (const e of V.envelopes) {
    U.openEnvelope(e.wire, { now: e.wire.issued_at });
    assert.equal(U.digest(Object.fromEntries(Object.entries(e.wire).filter(([k]) => k !== "sig"))), e.signing_digest, e.name);
    assert.equal(U.envelopeDigest(e.wire), e.digest, e.name);
    const { v, sig, from, ...fields } = e.wire;
    assert.equal(U.sealFields(U.signerFromSeed(seed(e.signer)), fields).sig, sig, e.name);
  }
});

test("every published rejection is refused here with the same code", () => {
  for (const r of V.rejections) assert.throws(() => U.openEnvelope(r.wire, { now: r.now }), (e) => e.code === r.code, r.name);
});

test("every published bad wire text is refused here with the same code", () => {
  for (const w of V.wire_text) assert.throws(() => U.strictParse(w.text), (e) => e.code === w.code, w.name);
});

test("selective disclosure: same commitments, same document digest, the published reveal opens", () => {
  const d = V.disclosure;
  const c = U.commit(d.identity, d.values, d.salts);
  assert.deepEqual({ ...c.commitments }, { ...d.commitments });
  assert.equal(c.digest, d.digest);
  assert.deepEqual({ ...U.openDisclosure(d.digest, d.reveal, ["doc_type", "monthly_income_cents"]) }, { doc_type: "paystub", monthly_income_cents: 512000 });
  assert.throws(() => U.openDisclosure(d.digest, c.reveal(["doc_type", "monthly_income_cents", "ssn"]), ["doc_type", "monthly_income_cents"]), (e) => e.code === "disclosure");
});

test("terms digest", () => assert.equal(U.termsDigest(V.terms.terms), V.terms.digest));

test("a full exchange inside this implementation, with replay refused", () => {
  const A = U.signerFromSeed(seed("alice")), B = U.signerFromSeed(seed("bob"));
  const cap = { name: "income-screen", version: 1, summary: "", accepts: ["doc_type", "monthly_income_cents"], requires: ["monthly_income_cents"], evidence: ["threshold-check"], max_ttl_ms: 300000 };
  const doc = U.commit("doc-9", { monthly_income_cents: 500000, doc_type: "paystub", ssn: "x" });
  const req = U.requestBody("income-screen", 1, { identity: doc.identity, digest: doc.digest, offerFields: ["monthly_income_cents", "doc_type"], requireEvidence: ["threshold-check"], maxTtlMs: 600000 });
  const request = U.seal(A, "request", req, { to: B.agent, ttlMs: 60000 });
  const terms = U.proposeTerms(cap, U.openEnvelope(request).body, { decider: B.agent, requester: A.agent });
  const offer = U.seal(B, "offer", { terms }, { to: A.agent, replyTo: request, ttlMs: 60000 });
  U.checkTerms(U.openEnvelope(offer).body.terms, req, { decider: B.agent, requester: A.agent });
  const accept = U.seal(A, "accept", { terms_digest: U.termsDigest(terms), disclosure: doc.reveal(terms.disclose) }, { to: B.agent, replyTo: offer, ttlMs: 60000 });
  const seen = U.openDisclosure(terms.subject.digest, U.openEnvelope(accept).body.disclosure, terms.disclose);
  assert.equal(seen.ssn, undefined);
  const decision = U.issueDecision(B, accept, terms, "pass", { evidence: { "threshold-check": { observed_cents: seen.monthly_income_cents } } });
  const ledger = new U.Ledger();
  const got = U.verifyDecision(decision, { terms, acceptDigest: U.envelopeDigest(accept), ledger });
  assert.ok(got.allowed);
  assert.throws(() => U.verifyDecision(decision, { terms, acceptDigest: U.envelopeDigest(accept), ledger }), (e) => e.code === "replayed");
  const tampered = JSON.parse(JSON.stringify(decision)); tampered.body.verdict = "pass"; tampered.body.reasons = ["edited"];
  assert.throws(() => U.verifyDecision(tampered, { terms, acceptDigest: U.envelopeDigest(accept), ledger: new U.Ledger() }), (e) => e.code === "signature");
});

test("crypto diagnostics name the one backend, the profile read once, and claim nothing about timing", () => {
  const d = U.cryptoDiagnostics();
  assert.equal(d.algorithm, "ed25519");
  assert.equal(d.frozen, true);
  assert.equal(d.constant_time_claimed, false);
  assert.throws(() => { d.backend = "other"; });   // frozen object: a caller cannot rewrite what was reported
});
