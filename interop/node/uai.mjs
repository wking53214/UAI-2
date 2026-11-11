// uai.mjs: an independent implementation of UAI-1 (docs/interop/UAI-1.md) in JavaScript.
//
// It shares no code with the Python reference (cns_interop). It is written from the spec and checked against the
// published answer keys: contracts/digest-vectors.json (the canonical digest) and contracts/uai-vectors.json
// (signed envelopes, disclosure commitments, terms). Signatures use Node's built-in Ed25519 (OpenSSL), not the
// Python package's own Ed25519. If the two implementations agree, it is because the spec is precise enough for two
// independent implementations to agree, which is the point.
//
// Scope: envelope, strict wire parsing, canonical digest, identity, pinned trust, manifests, negotiation, selective
// disclosure, decisions, a replay ledger with leases, signed revocation and rotation, and a RemoteDecisionGuard.
// Endorsement-based trust is in the Python reference only: a peer admitted only by endorsement is refused here.

import { createHash, createPrivateKey, createPublicKey, randomBytes, sign as edSign, verify as edVerify } from "node:crypto";

export const VERSION = "uai/1";
export const KINDS = new Set(["manifest", "endorsement", "request", "offer", "accept", "refuse", "decision", "revocation"]);
export const FIELDS = ["body", "conversation", "expires_at", "from", "id", "in_reply_to", "issued_at", "kind", "sig", "to", "v"];
export const MAX_INT = Number.MAX_SAFE_INTEGER;
export const MAX_DEPTH = 32;
export const VERDICTS = ["pass", "retry", "terminal_breach"];
const SIG_TAG = Buffer.from("uai/1 sig\n", "utf8");

export class Refused extends Error {
  constructor(code, reason) { super(`${code}: ${reason}`); this.code = code; this.reason = reason; }
}

// ---------------------------------------------------------------- strict JSON

// JSON.parse cannot be used: it accepts duplicate keys (keeping the last) and turns 1.0 into 1, so a float and an
// integer would digest alike here and differently in every implementation that keeps the distinction.
export function strictParse(text) {
  if (typeof text !== "string") throw new Refused("malformed", "the message is not text");
  if (Buffer.byteLength(text, "utf8") > 1 << 20) throw new Refused("malformed", "the message is larger than 1 MiB");
  let i = 0;
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  const fail = (why) => { throw new Refused("malformed", `the message is not JSON (${why} at ${i})`); };
  const value = (depth) => {
    if (depth > MAX_DEPTH + 2) fail("too deep");
    ws();
    const c = text[i];
    if (c === "{") {
      i++; const out = Object.create(null); ws();
      if (text[i] === "}") { i++; return out; }
      for (;;) {
        ws(); if (text[i] !== "\"") fail("expected a key");
        const k = str();
        if (Object.prototype.hasOwnProperty.call(out, k)) throw new Refused("malformed", `the key ${JSON.stringify(k)} appears twice`);
        ws(); if (text[i] !== ":") fail("expected :"); i++;
        out[k] = value(depth + 1); ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "}") { i++; return out; }
        fail("expected , or }");
      }
    }
    if (c === "[") {
      i++; const out = []; ws();
      if (text[i] === "]") { i++; return out; }
      for (;;) {
        out.push(value(depth + 1)); ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "]") { i++; return out; }
        fail("expected , or ]");
      }
    }
    if (c === "\"") return str();
    if (text.startsWith("true", i)) { i += 4; return true; }
    if (text.startsWith("false", i)) { i += 5; return false; }
    if (text.startsWith("null", i)) { i += 4; return null; }
    const m = /^-?(0|[1-9][0-9]*)([.eE][-+0-9.eE]*)?/.exec(text.slice(i));
    if (!m) fail("unexpected character");
    if (m[2]) throw new Refused("profile", `the number ${m[0]} is a float; UAI-1 carries integers only`);
    i += m[0].length;
    const n = Number(m[0]);
    if (!Number.isSafeInteger(n)) throw new Refused("profile", "an integer outside +/-(2**53 - 1)");
    return n;
  };
  const str = () => {
    i++; let out = "";
    for (;;) {
      if (i >= text.length) fail("unterminated string");
      const c = text[i];
      if (c === "\"") { i++; return out; }
      if (c === "\\") {
        const e = text[i + 1];
        const simple = { "\"": "\"", "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
        if (e in simple) { out += simple[e]; i += 2; continue; }
        if (e === "u" && /^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) { out += String.fromCharCode(parseInt(text.slice(i + 2, i + 6), 16)); i += 6; continue; }
        fail("bad escape");
      }
      if (c < " ") fail("control character in string");
      out += c; i++;
    }
  };
  const v = value(0); ws();
  if (i !== text.length) fail("trailing text");
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Refused("malformed", "the message is not a JSON object");
  return v;
}

// The same reading, from BYTES: the decoder is fatal, so invalid UTF-8 is refused instead of being replaced with U+FFFD
// (two receivers that decode differently would read different text out of the same bytes), and a BOM is kept so the
// parser refuses it. This is the entry point a transport should use; strictParse takes text that is already decoded.
export function strictParseBytes(buf) {
  if (!(buf instanceof Uint8Array)) throw new Refused("malformed", "the message is not bytes");
  if (buf.length > 1 << 20) throw new Refused("malformed", "the message is larger than 1 MiB");
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buf); }
  catch { throw new Refused("malformed", "the message is not UTF-8"); }
  return strictParse(text);
}

export function dumps(wire) { return JSON.stringify(sortDeep(wire)); }
function sortDeep(v) {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === "object") { const o = {}; for (const k of cpSort(Object.keys(v))) o[k] = sortDeep(v[k]); return o; }
  return v;
}

// ---------------------------------------------------------------- canonical digest (cns.gate.subject_digest)

const cpCompare = (a, b) => {
  const x = [...a], y = [...b];
  for (let k = 0; k < Math.min(x.length, y.length); k++) {
    const d = x[k].codePointAt(0) - y[k].codePointAt(0);
    if (d) return d;
  }
  return x.length - y.length;
};
const cpSort = (keys) => [...keys].sort(cpCompare);
const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

export function canonical(v) {
  if (v === null) return "n:";
  if (v === true) return "b:1";
  if (v === false) return "b:0";
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Refused("profile", "only integers within +/-(2**53 - 1) are carried");
    return `i:${v}:`;
  }
  if (typeof v === "string") return `s:${[...v].length}:${v}`; // length in code points, as Python counts it
  if (Array.isArray(v)) return `l:${v.length}:` + v.map(canonical).join("");
  if (isPlainObject(v)) {
    const keys = cpSort(Object.keys(v));
    return `d:${keys.length}:` + keys.map((k) => canonical(k) + canonical(v[k])).join("");
  }
  throw new Refused("profile", `cannot carry a ${typeof v}`);
}

export const digest = (v) => createHash("sha256").update(canonical(v), "utf8").digest("hex");

export function checkProfile(v, where = "body", depth = 0) {
  if (depth > MAX_DEPTH) throw new Refused("profile", `${where} nests deeper than ${MAX_DEPTH} levels`);
  if (v === null || typeof v === "boolean") return;
  if (typeof v === "number") { if (!Number.isSafeInteger(v)) throw new Refused("profile", `${where} holds a non-integer or an integer out of range`); return; }
  if (typeof v === "string") { if (!v.isWellFormed()) throw new Refused("profile", `${where} holds text that is not valid Unicode`); return; }
  if (Array.isArray(v)) { v.forEach((x, k) => checkProfile(x, `${where}[${k}]`, depth + 1)); return; }
  if (isPlainObject(v)) { for (const k of Object.keys(v)) { checkProfile(k, where, depth + 1); checkProfile(v[k], `${where}.${k}`, depth + 1); } return; }
  throw new Refused("profile", `${where} holds a ${typeof v}`);
}

// ---------------------------------------------------------------- identity

export const AGENT_PREFIX = "uai:ed25519:";
const AGENT_RE = /^uai:ed25519:[0-9a-f]{64}$/;
export const isAgentId = (v) => typeof v === "string" && AGENT_RE.test(v);
const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI = Buffer.from("302a300506032b6570032100", "hex");

export function signerFromSeed(seed) {
  if (!Buffer.isBuffer(seed) || seed.length !== 32) throw new Error("a signer's key is a 32-byte seed");
  const key = createPrivateKey({ key: Buffer.concat([PKCS8, seed]), format: "der", type: "pkcs8" });
  const pub = createPublicKey(key).export({ format: "der", type: "spki" }).subarray(SPKI.length);
  const agent = AGENT_PREFIX + Buffer.from(pub).toString("hex");
  return { agent, sign: (msg) => edSign(null, msg, key) };
}

// The canonical encodings of the eight points of small order. A key among them can be "signed for" by anyone, so
// none is accepted as a public key. cns_interop/tests/test_uai_vectors.py recomputes this list from the curve.
export const SMALL_ORDER = new Set([
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]);
const P25519 = (1n << 255n) - 19n;

// A point encoding is canonical when y < p and the sign bit is clear wherever x is 0 (y = 1 or y = p - 1).
// OpenSSL accepts some non-canonical encodings; the Python reference does not, so neither does this.
function canonicalPoint(hex) {
  const b = Buffer.from(hex, "hex");
  const sign = b[31] >> 7;
  const yb = Buffer.from(b); yb[31] &= 0x7f;
  const y = BigInt("0x" + Buffer.from(yb).reverse().toString("hex"));
  if (y >= P25519) return false;
  if (sign && (y === 1n || y === P25519 - 1n)) return false;
  return true;
}

// What is in force, for an operator to compare with what was approved. Node has one verifier (OpenSSL Ed25519 behind the
// same strict pre-checks as Python) and no runtime switch, so there is nothing to downgrade; the profile is read once.
const PROFILE = process.env.UAI_PROFILE === "production" ? "production" : "default";
export const cryptoDiagnostics = () => Object.freeze({
  algorithm: "ed25519", backend: "node:crypto (OpenSSL)", profile: PROFILE, frozen: true, constant_time_claimed: false,
});

export function verifySig(agent, msg, sigHex) {
  if (!isAgentId(agent) || !/^[0-9a-f]{128}$/.test(sigHex)) return false;
  const pubHex = agent.slice(AGENT_PREFIX.length);
  if (SMALL_ORDER.has(pubHex) || !canonicalPoint(pubHex) || !canonicalPoint(sigHex.slice(0, 64))) return false;
  try {
    const pub = createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(agent.slice(AGENT_PREFIX.length), "hex")]), format: "der", type: "spki" });
    return edVerify(null, msg, pub, Buffer.from(sigHex, "hex"));
  } catch { return false; }
}

// ---------------------------------------------------------------- envelope

const HEX32 = /^[0-9a-f]{32}$/, HEX64 = /^[0-9a-f]{64}$/;
const unsignedOf = (w) => { const u = { ...w }; delete u.sig; return u; };
const signingInput = (unsigned) => Buffer.concat([SIG_TAG, Buffer.from(digest(unsigned), "ascii")]);
export const envelopeDigest = (wire) => digest(wire);

export function sealFields(signer, fields) {
  const unsigned = { v: VERSION, ...fields, from: signer.agent };
  checkProfile(unsigned.body);
  return { ...unsigned, sig: Buffer.from(signer.sign(signingInput(unsigned))).toString("hex") };
}

export function seal(signer, kind, body, { to = "", replyTo = null, ttlMs = null, now = Date.now() } = {}) {
  if (!KINDS.has(kind)) throw new Error(`unknown kind ${kind}`);
  const id = randomBytes(16).toString("hex");
  return sealFields(signer, {
    kind, id, to, conversation: replyTo ? replyTo.conversation : id, in_reply_to: replyTo ? envelopeDigest(replyTo) : "",
    issued_at: now, expires_at: ttlMs === null ? null : now + ttlMs, body,
  });
}

// Count the values without recursion and stop past `limit`: the work is at most `limit` steps however big the message is,
// so a receiver can bound what an unauthenticated message makes it do before the signature is touched.
export function boundedNodes(value, limit) {
  const tooMany = () => new Refused("profile", `the message holds more than ${limit} values, which this receiver does not read`);
  let seen = 1; const stack = [value];
  if (seen > limit) throw tooMany();
  while (stack.length) {
    const v = stack.pop();
    if (Array.isArray(v)) { seen += v.length; if (seen > limit) throw tooMany(); for (const x of v) stack.push(x); }
    else if (v !== null && typeof v === "object") {
      const keys = Object.keys(v); seen += 2 * keys.length; if (seen > limit) throw tooMany();
      for (const k of keys) { stack.push(k); stack.push(v[k]); }
    }
  }
  return seen;
}

export function openEnvelope(wire, { now = Date.now(), skewMs = 120000, audience = null, kinds = null, maxNodes = null } = {}) {
  const need = (ok, why) => { if (!ok) throw new Refused("malformed", why); };
  need(isPlainObject(wire), "an envelope is a mapping");
  const keys = cpSort(Object.keys(wire));
  need(keys.length === FIELDS.length && keys.every((k, n) => k === FIELDS[n]), "not exactly the UAI-1 fields");
  if (wire.v !== VERSION) throw new Refused("version", `this receiver speaks ${VERSION}`);
  need(typeof wire.kind === "string" && KINDS.has(wire.kind), "unknown kind");
  if (kinds && !kinds.has(wire.kind)) throw new Refused("kind", `a ${wire.kind} is not what this step accepts`);
  need(typeof wire.id === "string" && HEX32.test(wire.id), "id is not 32 hex digits");
  need(isAgentId(wire.from), "from is not an agent identity");
  need(wire.to === "" || isAgentId(wire.to), "to is not an agent identity or empty");
  need(typeof wire.conversation === "string" && HEX32.test(wire.conversation), "conversation is not 32 hex digits");
  need(wire.in_reply_to === "" || (typeof wire.in_reply_to === "string" && HEX64.test(wire.in_reply_to)), "in_reply_to is not a digest");
  need(Number.isSafeInteger(wire.issued_at) && wire.issued_at >= 0, "issued_at is not a time in ms");
  need(wire.expires_at === null || (Number.isSafeInteger(wire.expires_at) && wire.expires_at > wire.issued_at), "expires_at is not after issued_at");
  need(isPlainObject(wire.body), "body is not a mapping");
  need(typeof wire.sig === "string" && /^[0-9a-f]{128}$/.test(wire.sig), "sig is not 128 hex digits");
  if (maxNodes !== null) boundedNodes(wire.body, maxNodes);
  checkProfile(wire.body);
  if (!verifySig(wire.from, signingInput(unsignedOf(wire)), wire.sig)) throw new Refused("signature", "the signature does not verify as the sender");
  if (wire.issued_at > now + skewMs) throw new Refused("not_yet_valid", "dated in the future beyond the allowed skew");
  if (wire.expires_at !== null && now >= wire.expires_at) throw new Refused("expired", "the envelope has expired");
  if (audience !== null && wire.to !== audience) throw new Refused("audience", "not addressed to this receiver");
  return wire;
}

// ---------------------------------------------------------------- trust, ledger

export class PinnedTrust {
  // `revocations` is a RevocationStore. With `maxStalenessMs`, a store never refreshed, or refreshed longer ago than
  // that, makes admit refuse ("unavailable"): the receiver cannot rule out a revocation it has not heard.
  constructor(pinned = [], revoked = [], { revocations = null, maxStalenessMs = null, followRotation = false } = {}) {
    this.pinned = new Set(pinned); this.revoked = new Set(revoked);
    this.revocations = revocations; this.maxStalenessMs = maxStalenessMs; this.followRotation = followRotation;
  }
  isRevoked(subject, now = Date.now()) {
    if (this.revoked.has(subject)) return true;
    if (!this.revocations) return false;
    if (this.maxStalenessMs !== null) {
      const age = this.revocations.ageMs(now);
      if (age === null || age > this.maxStalenessMs) throw new Refused("unavailable", "this receiver's revocation list is too old to rule out a revocation");
    }
    return this.revocations.isRevoked(subject, now);
  }
  admit(agent, { now = Date.now() } = {}) {
    if (this.isRevoked(agent, now)) throw new Refused("untrusted", "this receiver has revoked that identity");
    if (this.pinned.has(agent)) return { agent, via: "pinned" };
    if (this.followRotation && this.revocations) {
      const before = this.revocations.predecessorOf(agent);
      if (before !== null && this.pinned.has(before)) return { agent, via: "rotated", authority: before };
    }
    throw new Refused("untrusted", "the identity is not pinned and no endorsement admits it");
  }
}

// One state machine for spend, reserve, commit and release, as in cns_interop/ledger.py. An entry is committed or
// leased. An expired message, or a lapsed lease, is forgotten; "expired" is judged by the EARLIER of the verifier's
// clock and this host's, so a verifier running behind never finds a message it still accepts already forgotten.
export class Ledger {
  constructor({ keepMs = 120000 } = {}) { this.seen = new Map(); this.keepMs = keepMs; }
  _entry(sender, id, now) {
    const wall = Date.now(), cutoff = Math.min(now, wall) - this.keepMs;
    for (const [k, e] of this.seen) if ((e.expiresAt !== null && e.expiresAt <= cutoff) || (e.leaseUntil !== null && e.leaseUntil <= now)) this.seen.delete(k);
    return this.seen.get(`${sender} ${id}`);
  }
  spend(sender, id, expiresAt = null, { now = Date.now() } = {}) {
    if (this._entry(sender, id, now)) throw new Refused("replayed", "this message was already accepted once");
    this.seen.set(`${sender} ${id}`, { expiresAt, leaseUntil: null, token: null });
  }
  reserve(sender, id, expiresAt = null, { leaseMs, now = Date.now() } = {}) {
    if (!Number.isSafeInteger(leaseMs) || leaseMs <= 0 || leaseMs > 3600000) throw new RangeError("leaseMs is a positive integer, at most 3600000");
    if (this._entry(sender, id, now)) throw new Refused("replayed", "this message was already accepted once or is being redeemed");
    const token = randomBytes(16).toString("hex"), leaseUntil = now + leaseMs;
    this.seen.set(`${sender} ${id}`, { expiresAt, leaseUntil, token });
    return { sender, id, expiresAt, token, leaseUntil, key: `${sender} ${id}` };
  }
  commit(r, { now = Date.now() } = {}) {
    const cur = this._entry(r.sender, r.id, now);
    if (cur && cur.token !== r.token) throw new Refused("lease_lost", "the message was taken by another redemption after this lease lapsed");
    this.seen.set(r.key, { expiresAt: r.expiresAt, leaseUntil: null, token: null });
  }
  release(r, { now = Date.now() } = {}) {
    const cur = this._entry(r.sender, r.id, now);
    if (!cur) return;
    if (cur.token !== r.token) throw new Refused("lease_lost", "only the holder of a lease can release it");
    this.seen.delete(r.key);
  }
}

// ---------------------------------------------------------------- revocation and rotation (cns_interop/revocation.py)

const HEX32_ID = /^[0-9a-f]{32}$/;
export function readStatement(wire, { authorities = [], now = Date.now() } = {}) {
  const env = openEnvelope(wire, { now, kinds: new Set(["revocation"]) });
  const b = env.body;
  if (cpSort(Object.keys(b)).join() !== "action,effective_at,reason,subject,successor") throw new Refused("malformed", "a revocation body has exactly: action, effective_at, reason, subject, successor");
  const { subject, action, successor, reason, effective_at: eff } = b;
  if (typeof subject !== "string" || !(isAgentId(subject) || HEX32_ID.test(subject))) throw new Refused("malformed", "the subject is an agent identity or an endorsement id");
  if (!["revoke", "rotate"].includes(action) || typeof reason !== "string") throw new Refused("malformed", "action is revoke or rotate, and reason is text");
  if (!Number.isSafeInteger(eff) || eff < 0) throw new Refused("malformed", "effective_at is a time in ms");
  if (action === "revoke" && successor !== "") throw new Refused("malformed", "a revoke names no successor");
  if (action === "rotate") {
    if (!isAgentId(successor) || successor === subject || !isAgentId(subject)) throw new Refused("malformed", "a rotate names another agent identity as its successor");
    if (env.from !== subject) throw new Refused("untrusted", "only an identity can rotate itself");
  }
  if (env.from !== subject && !new Set(authorities).has(env.from)) throw new Refused("untrusted", "a revocation must come from the subject itself or an authority this receiver lists");
  return { subject, action, successor, reason, effectiveAt: eff, signer: env.from, id: env.id, envelope: env };
}

export class RevocationStore {
  constructor() { this.rows = new Map(); this.successors = new Map(); this.freshAt = null; }
  accept(wire, { authorities = [], now = Date.now() } = {}) {
    const st = readStatement(wire, { authorities, now });
    const have = this.rows.get(st.subject);
    if (have && have.action === "rotate" && st.action === "revoke" && st.signer !== st.subject) {
      // An authority revoking a key that already named a successor: withdraw the successor too.
      this.rows.set(st.subject, { action: "revoke", successor: "", effectiveAt: have.effectiveAt, signer: st.signer });
      this.successors.delete(have.successor);
    }
    if (!have) {
      this.rows.set(st.subject, { action: st.action, successor: st.successor, effectiveAt: st.effectiveAt, signer: st.signer });
      if (st.action === "rotate" && !this.successors.has(st.successor)) this.successors.set(st.successor, st.subject);
    }
    return st;
  }
  isRevoked(subject, now = Date.now()) { const r = this.rows.get(subject); return !!r && now >= r.effectiveAt; }
  predecessorOf(agent) { return this.successors.has(agent) ? this.successors.get(agent) : null; }
  markFresh(now = Date.now()) { this.freshAt = now; }
  ageMs(now = Date.now()) { return this.freshAt === null ? null : Math.max(0, now - this.freshAt); }
}

// ---------------------------------------------------------------- disclosure

const SALT = /^[0-9a-f]{32}$/;
export const commitment = (name, salt, value) => digest({ field: name, salt, value });
export const rootOf = (commitments) => digest({ commitments });

export function commit(identity, values, salts = null) {
  const s = salts || Object.fromEntries(Object.keys(values).map((k) => [k, randomBytes(16).toString("hex")]));
  checkProfile(values);
  const commitments = Object.fromEntries(Object.entries(values).map(([k, v]) => [k, commitment(k, s[k], v)]));
  return {
    identity, values, salts: s, commitments, digest: rootOf(commitments),
    reveal: (names) => ({ commitments, disclosed: Object.fromEntries(cpSort(names).map((n) => [n, { salt: s[n], value: values[n] }])) }),
  };
}

export function openDisclosure(rootDigest, presented, agreed) {
  const no = (why) => { throw new Refused("disclosure", why); };
  if (!isPlainObject(presented) || cpSort(Object.keys(presented)).join() !== "commitments,disclosed") no("a disclosure is exactly commitments and disclosed");
  const { commitments, disclosed } = presented;
  if (!isPlainObject(commitments) || !Object.values(commitments).every((c) => typeof c === "string" && HEX64.test(c))) no("bad commitments");
  if (rootOf(commitments) !== rootDigest) no("the commitments do not produce the document digest the terms name");
  if (!isPlainObject(disclosed)) no("disclosed must be a mapping");
  const want = new Set(agreed);
  const extra = Object.keys(disclosed).filter((k) => !want.has(k));
  if (extra.length) no("fields were disclosed that the terms do not allow: " + cpSort(extra).join(", "));
  const out = Object.create(null);
  for (const name of cpSort([...want])) {
    const o = Object.hasOwn(disclosed, name) ? disclosed[name] : undefined;
    if (!o) no("agreed fields were not disclosed: " + name);
    if (!isPlainObject(o) || cpSort(Object.keys(o)).join() !== "salt,value" || typeof o.salt !== "string" || !SALT.test(o.salt)) no(`the opening of ${name} is malformed`);
    if (!Object.hasOwn(commitments, name) || commitments[name] !== commitment(name, o.salt, o.value)) no(`the opening of ${name} does not match its commitment`);
    out[name] = o.value;
  }
  return out;
}

// ---------------------------------------------------------------- manifest, negotiation

const NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const names = (v, what) => {
  if (!Array.isArray(v) || !v.every((n) => typeof n === "string" && NAME.test(n)) || new Set(v).size !== v.length) throw new Refused("malformed", `${what} is a list of distinct lowercase names`);
  return cpSort(v);
};

export function publish(signer, name, implementation, capabilities, { now = Date.now(), ttlMs = 86400000 } = {}) {
  return seal(signer, "manifest", { name, implementation, protocols: [VERSION], capabilities, endorsements: [] }, { now, ttlMs });
}

export function readManifest(wire, { now = Date.now(), trust = null } = {}) {
  const env = openEnvelope(wire, { now, kinds: new Set(["manifest"]) });
  const b = env.body;
  if (cpSort(Object.keys(b)).join() !== "capabilities,endorsements,implementation,name,protocols") throw new Refused("malformed", "manifest body fields");
  if (!Array.isArray(b.protocols) || !b.protocols.includes(VERSION)) throw new Refused("version", "no shared protocol version");
  for (const c of b.capabilities) {
    if (cpSort(Object.keys(c)).join() !== "accepts,evidence,max_ttl_ms,name,requires,summary,version") throw new Refused("malformed", "capability fields");
    names(c.accepts, "accepts"); names(c.requires, "requires"); names(c.evidence, "evidence");
    if (!c.requires.every((r) => c.accepts.includes(r))) throw new Refused("malformed", "requires a field it does not accept");
  }
  if (trust) trust.admit(env.from);
  return env;
}

export function requestBody(capability, version, { identity, digest: d, offerFields, requireEvidence = [], maxTtlMs }) {
  return { capability, version, subject: { identity, digest: d }, offer_fields: cpSort(offerFields), require_evidence: cpSort(requireEvidence), max_ttl_ms: maxTtlMs };
}

const posInt = (v) => Number.isSafeInteger(v) && v > 0;
export function readRequest(b) {
  if (!isPlainObject(b) || cpSort(Object.keys(b)).join() !== "capability,max_ttl_ms,offer_fields,require_evidence,subject,version") throw new Refused("malformed", "request body fields");
  if (typeof b.capability !== "string" || !NAME.test(b.capability) || !posInt(b.version)) throw new Refused("malformed", "a request names a capability and a positive version");
  if (!posInt(b.max_ttl_ms)) throw new Refused("malformed", "max_ttl_ms is a positive integer");
  if (!isPlainObject(b.subject) || cpSort(Object.keys(b.subject)).join() !== "digest,identity" || !["identity", "digest"].every((k) => typeof b.subject[k] === "string" && b.subject[k] !== "")) throw new Refused("malformed", "a subject is exactly identity and digest, both non-empty text");
  return { ...b, offer_fields: names(b.offer_fields, "offer_fields"), require_evidence: names(b.require_evidence, "require_evidence") };
}

export function proposeTerms(cap, request, { decider, requester }) {
  const req = readRequest(request);
  if (req.capability !== cap.name || req.version !== cap.version) throw new Refused("capability", "a different capability or version");
  const withheld = cap.requires.filter((f) => !req.offer_fields.includes(f));
  if (withheld.length) throw new Refused("terms", "the capability must see fields the requester will not disclose: " + cpSort(withheld).join(", "));
  const unavailable = req.require_evidence.filter((e) => !cap.evidence.includes(e));
  if (unavailable.length) throw new Refused("terms", "the requester needs evidence this capability does not produce: " + unavailable.join(", "));
  return {
    capability: cap.name, version: cap.version, decider, requester, subject: req.subject,
    disclose: cpSort(req.offer_fields.filter((f) => cap.accepts.includes(f))), evidence: req.require_evidence,
    decision_ttl_ms: Math.min(cap.max_ttl_ms, req.max_ttl_ms),
  };
}

export function checkTerms(terms, request, { decider, requester }) {
  const req = readRequest(request);
  const no = (why) => { throw new Refused("terms", why); };
  if (!isPlainObject(terms) || cpSort(Object.keys(terms)).join() !== "capability,decider,decision_ttl_ms,disclose,evidence,requester,subject,version") throw new Refused("malformed", "terms fields");
  if (terms.decider !== decider || terms.requester !== requester) no("the terms name a different decider or requester");
  if (terms.capability !== req.capability || terms.version !== req.version) no("a different capability or version");
  if (digest(terms.subject) !== digest(req.subject)) no("a different document");
  if (!names(terms.disclose, "disclose").every((f) => req.offer_fields.includes(f))) no("the terms ask to see fields that were not offered");
  if (names(terms.evidence, "evidence").join() !== req.require_evidence.join()) no("not exactly the evidence that was required");
  if (!Number.isSafeInteger(terms.decision_ttl_ms) || terms.decision_ttl_ms <= 0 || terms.decision_ttl_ms > req.max_ttl_ms) no("the decision would live too long");
  return terms;
}

export const termsDigest = (terms) => digest(terms);

// ---------------------------------------------------------------- decisions

export function issueDecision(signer, accept, terms, verdict, { reasons = [], evidence = {}, cnsRoot = "", now = Date.now() } = {}) {
  if (!VERDICTS.includes(verdict)) throw new Error("unknown verdict");
  if (signer.agent !== terms.decider) throw new Error("only the decider the terms name can issue this decision");
  const kinds = cpSort(Object.keys(evidence));
  if (verdict === "pass" && kinds.join() !== terms.evidence.join()) throw new Error("a pass must carry exactly the evidence the terms require");
  const ev = kinds.map((k) => ({ kind: k, content: evidence[k], digest: digest(evidence[k]) }));
  return seal(signer, "decision", { verdict, terms_digest: termsDigest(terms), subject: terms.subject, reasons, evidence: ev, cns_root: cnsRoot },
    { to: terms.requester, replyTo: accept, ttlMs: terms.decision_ttl_ms, now });
}

const TERMS_FIELDS = "capability,decider,decision_ttl_ms,disclose,evidence,requester,subject,version";

// A ledger that cannot give a definite answer (anything thrown that is not a refusal) means there is no authoritative
// state, so the answer is "unavailable": permission is never inferred from a failure to check.
function redeem(ledger, env, now, leaseMs) {
  try {
    if (leaseMs !== null && leaseMs !== undefined) {
      if (typeof ledger.reserve !== "function") throw new RangeError("leaseMs needs a ledger with reserve, commit and release");
      return ledger.reserve(env.from, env.id, env.expires_at, { leaseMs, now });
    }
    ledger.spend(env.from, env.id, env.expires_at, { now });
    return null;
  } catch (e) {
    if (e instanceof Refused || e instanceof RangeError) throw e;
    throw new Refused("unavailable", `the ledger could not say whether this decision is new, so it is not accepted (${e && e.name})`);
  }
}

export function verifyDecision(wire, { terms, acceptDigest, ledger, now = Date.now(), leaseMs = null }) {
  if (!isPlainObject(terms) || cpSort(Object.keys(terms)).join() !== TERMS_FIELDS) throw new Refused("terms", "the terms to check against are not complete terms");
  const env = openEnvelope(wire, { now, audience: terms.requester, kinds: new Set(["decision"]) });
  if (env.from !== terms.decider) throw new Refused("untrusted", "signed by someone other than the decider the terms name");
  if (env.in_reply_to !== acceptDigest) throw new Refused("terms", "the decision answers a different accept");
  const b = env.body;
  if (cpSort(Object.keys(b)).join() !== "cns_root,evidence,reasons,subject,terms_digest,verdict") throw new Refused("malformed", "decision body fields");
  if (b.terms_digest !== termsDigest(terms)) throw new Refused("terms", "made under different terms");
  if (digest(b.subject) !== digest(terms.subject)) throw new Refused("subject", "judged a different document");
  if (!VERDICTS.includes(b.verdict)) throw new Refused("malformed", "unknown verdict");
  if (env.expires_at === null || env.expires_at - env.issued_at > terms.decision_ttl_ms) throw new Refused("terms", "lives longer than the terms allow");
  if (!Array.isArray(b.evidence) || !Array.isArray(b.reasons) || !b.reasons.every((r) => typeof r === "string")) throw new Refused("malformed", "evidence and reasons are lists");
  if (typeof b.cns_root !== "string") throw new Refused("malformed", "cns_root is text and evidence a list");
  const evidence = Object.create(null);
  for (const it of b.evidence) {
    if (!isPlainObject(it) || cpSort(Object.keys(it)).join() !== "content,digest,kind" || typeof it.kind !== "string" || !isPlainObject(it.content) || it.kind in evidence) throw new Refused("malformed", "evidence item");
    if (digest(it.content) !== it.digest) throw new Refused("malformed", `evidence ${it.kind} does not match its digest`);
    evidence[it.kind] = it.content;
  }
  const kinds = cpSort(Object.keys(evidence));
  if (!kinds.every((k) => terms.evidence.includes(k))) throw new Refused("terms", "evidence the terms did not ask for");
  if (b.verdict === "pass" && kinds.join() !== terms.evidence.join()) throw new Refused("terms", "a pass without the required evidence");
  const reservation = redeem(ledger, env, now, leaseMs);
  return { verdict: b.verdict, allowed: b.verdict === "pass", reasons: b.reasons, evidence, subject: b.subject, cnsRoot: b.cns_root, envelope: env, reservation };
}

// Closed until a verified, allowed decision opens it; then permits one action on that one document. Its own
// configuration, never the caller's, says who it acts for, which capability it protects, whom it trusts, and where it
// remembers spent decisions. Mirrors cns_interop.decision.RemoteDecisionGuard.
export class RemoteDecisionGuard {
  constructor(subjectOf, { actingFor, capability, trust, ledger, clock = Date.now, grants = null, action = null }) {
    if (typeof subjectOf !== "function") throw new Error("subjectOf must read [identity, digest] from an artifact");
    if (!isAgentId(actingFor)) throw new Error("actingFor is the identity this guard acts for");
    if (!Array.isArray(capability) || capability.length !== 2 || typeof capability[0] !== "string" || !NAME.test(capability[0]) || !Number.isSafeInteger(capability[1]) || capability[1] < 1) throw new Error("capability is the [name, version] this guard protects");
    if (!trust || typeof trust.admit !== "function") throw new Error("a guard needs its own trust policy for deciders");
    if ((grants === null) !== (action === null) || (action !== null && (typeof action !== "string" || !action))) throw new Error("grants and action go together: the guard then acts only under the receiver's own policy");
    Object.assign(this, { subjectOf, actingFor, capability, trust, ledger, clock, grants, action });
    this.permit = null;
    this.approved = null; this.decider = null; this.expiresAt = null; this.spent = false; this.reservation = null; this.closed = false;
  }
  authorize(wire, { terms, acceptDigest, leaseMs = null, approval = null }) {
    if (this.approved !== null) throw new Error("this guard was already authorized; one guard serves one decision");
    if (!isPlainObject(terms) || terms.requester !== this.actingFor) throw new Refused("audience", "the terms are for a requester this guard does not act for");
    if (terms.capability !== this.capability[0] || terms.version !== this.capability[1] || !Number.isSafeInteger(terms.version)) throw new Refused("terms", "the decision was negotiated for a different capability or version than this guard protects");
    if (typeof this.clock.sync === "function") this.clock.sync();   // a trusted clock (pg.mjs TrustedClock) is re-read from its reference for EVERY decision
    const now = this.clock();
    this.trust.admit(typeof terms.decider === "string" ? terms.decider : "", { now });
    if (this.grants !== null && leaseMs === null) leaseMs = 30000;   // a refusal a person can cure must not burn the decision
    const got = verifyDecision(wire, { terms, acceptDigest, ledger: this.ledger, now, leaseMs });
    if (!got.allowed) {
      if (got.reservation) this._finish(got.reservation, true);
      throw new Refused("refused", "the decision is not a pass: " + got.reasons.join("; "));
    }
    if (this.grants !== null) {
      try { this.permit = this.grants.permit(this.action, got, terms, { approval, now }); } catch (e) {
        if (e instanceof Refused && got.reservation) this._finish(got.reservation, false);   // give the decision back: approval may yet come
        throw e;
      }
    }
    this.approved = [got.subject.identity, got.subject.digest]; this.decider = got.envelope.from;
    this.expiresAt = got.envelope.expires_at; this.reservation = got.reservation;
    return got;
  }
  revoke(agent) {
    if (!isAgentId(agent)) throw new Error("revoke takes an agent identity");
    this.trust.revoked.add(agent);
  }
  call(artifact) {
    let seen;
    try { seen = this.subjectOf(artifact); if (!Array.isArray(seen) || seen.length !== 2) return false; } catch { return false; }
    if (this.approved === null || this.spent) return false;
    if (this.grants !== null && this.permit === null) return false;
    try { if (this.trust.isRevoked(this.decider, this.clock())) return false; } catch { return false; }
    if (this.expiresAt !== null && this.clock() >= this.expiresAt) return false;
    if (seen[0] !== this.approved[0] || seen[1] !== this.approved[1]) return false;
    this.spent = true;
    return true;
  }
  _finish(reservation, commit) {
    try { commit ? this.ledger.commit(reservation, { now: this.clock() }) : this.ledger.release(reservation, { now: this.clock() }); }
    catch (e) {
      if (e instanceof Refused) throw e;
      throw new Refused("unavailable", `the ledger did not confirm the ${commit ? "commit" : "release"} (${e && e.name})`);
    }
  }
  complete() {
    if (!this.reservation || this.closed || !this.spent) throw new Error("complete() follows a leased authorize and a permitted call, once");
    this.closed = true; this._finish(this.reservation, true);
    if (this.permit) this.permit.complete();
  }
  abort() {
    if (!this.reservation || this.closed) throw new Error("abort() follows a leased authorize, once, and not after complete()");
    this.closed = true; this.spent = true; this._finish(this.reservation, false);
    if (this.permit) this.permit.abort();
  }
  get idempotencyKey() { return this.reservation ? this.reservation.key : null; }
}
