// grants.mjs: the RECEIVER's side of UAI-1 in Node: purpose-bound grants, human approvals, single-use permits, durable
// withdrawals, a durable permit ledger and a hash-chained audit record. It mirrors cns_interop/grants.py and the
// SqliteLedger in cns_interop/ledger.py, rule for rule, and shares their on-disk formats where it can (the SQLite ledger
// and grant store open the same files as Python), so a decision spent or a grant withdrawn by one language is seen by the
// other. A signature never opens an action here: only a permit does, and only the receiver's own grants make one.
//
// Scope and honest limits (the same as the Python single-host stores):
//   * SQLite stores are for processes on ONE host. A Node receiver on several hosts shares the decision and permit LEDGERS
//     in PostgreSQL through pg.mjs (act.mjs --ledger-backend postgres), and the shared PostgreSQL withdrawals and audit chain
//     are pg_policy.mjs (PostgresGrantStore as `store`, PostgresAudit as `auditSink`); these SQLite and file stores are the
//     single-host alternative.
//   * The audit file is chained like Python's, but Node serialises writers with an exclusive lock FILE and Python with flock.
//     Do not point both languages at one audit file: each language's lock is invisible to the other.
//   * node:sqlite is experimental in Node 22; Node prints a warning. Nothing here is a claim that it is stable.

import { DatabaseSync } from "node:sqlite";
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, unlinkSync, writeSync } from "node:fs";
import { dirname } from "node:path";
import { randomBytes } from "node:crypto";
import { Refused, MAX_INT, digest, isAgentId, verifySig, termsDigest, strictParse } from "./uai.mjs";

const APPROVAL_TAG = Buffer.from("uai/1 approval\n", "utf8");
const TERMS_KEYS = "capability,decider,decision_ttl_ms,disclose,evidence,requester,subject,version";
const MAX_LEASE_MS = 3600 * 1000;
const ZERO = "0".repeat(64);
const mkParent = (path) => mkdirSync(dirname(path), { recursive: true });
const isInt = (v) => Number.isSafeInteger(v);

// ------------------------------------------------------------------------------------------------ the durable stores

// The same table and the same steps as Python's SqliteLedger, so both languages share one permit ledger file.
export class SqliteLedger {
  constructor(path, { keepMs = 120000, busyMs = 5000 } = {}) {
    this.path = path; this.keepMs = keepMs; this.busyMs = busyMs;
    mkParent(path);
    try {
      this._with((db) => db.exec("CREATE TABLE IF NOT EXISTS spent (sender TEXT NOT NULL, id TEXT NOT NULL, expires_at INTEGER, lease_until INTEGER, token TEXT, PRIMARY KEY (sender, id))"));
    } catch (e) { throw new Refused("unavailable", `the ledger database cannot be opened (${e && e.message})`); }
  }
  _with(fn) {
    const db = new DatabaseSync(this.path, { timeout: this.busyMs });
    try { db.exec("PRAGMA journal_mode=WAL"); db.exec("PRAGMA synchronous=FULL"); return fn(db); } finally { db.close(); }
  }
  _mutate(sender, id, now, step) {
    const t = now ?? Date.now(), cutoff = Math.min(t, Date.now()) - this.keepMs;
    try {
      return this._with((db) => {
        db.exec("BEGIN IMMEDIATE");
        try {
          db.prepare("DELETE FROM spent WHERE (expires_at IS NOT NULL AND expires_at <= ?) OR (lease_until IS NOT NULL AND lease_until <= ?)").run(cutoff, t);
          const row = db.prepare("SELECT expires_at, lease_until, token FROM spent WHERE sender=? AND id=?").get(sender, id);
          let cur = null;
          if (row) { cur = { sender, id, expiresAt: row.expires_at }; if (row.lease_until !== null) { cur.leaseUntil = row.lease_until; cur.token = row.token; } }
          const next = step(cur, t);
          db.prepare("DELETE FROM spent WHERE sender=? AND id=?").run(sender, id);
          if (next) db.prepare("INSERT INTO spent VALUES (?,?,?,?,?)").run(sender, id, next.expiresAt, next.leaseUntil ?? null, next.token ?? null);
          db.exec("COMMIT");
          return next ?? {};
        } catch (e) { try { db.exec("ROLLBACK"); } catch { /* the original error is the one that matters */ } throw e; }
      });
    } catch (e) {
      if (e instanceof Refused) throw e;
      throw new Refused("unavailable", `the ledger database did not answer (${e && e.message})`);
    }
  }
  spend(sender, id, expiresAt = null, { now } = {}) {
    this._mutate(sender, id, now, (cur) => {
      if (cur) throw new Refused("replayed", cur.leaseUntil === undefined ? "this message was already accepted once" : "this message is being redeemed right now");
      return { sender, id, expiresAt };
    });
  }
  reserve(sender, id, expiresAt = null, { leaseMs, now } = {}) {
    if (!isInt(leaseMs) || leaseMs <= 0 || leaseMs > MAX_LEASE_MS) throw new RangeError(`leaseMs is a positive integer, at most ${MAX_LEASE_MS}`);
    const token = randomBytes(16).toString("hex");
    const e = this._mutate(sender, id, now, (cur, t) => {
      if (cur) throw new Refused("replayed", cur.leaseUntil === undefined ? "this message was already accepted once" : "this message is being redeemed right now");
      return { sender, id, expiresAt, leaseUntil: t + leaseMs, token };
    });
    return { sender, id, expiresAt, token, leaseUntil: e.leaseUntil, fence: 0, key: `${sender} ${id}` };
  }
  commit(r, { now } = {}) {
    this._mutate(r.sender, r.id, now, (cur) => {
      if (cur && cur.token !== r.token) throw new Refused("lease_lost", "the message was taken by another redemption after this lease lapsed");
      return { sender: r.sender, id: r.id, expiresAt: r.expiresAt };
    });
  }
  release(r, { now } = {}) {
    this._mutate(r.sender, r.id, now, (cur) => {
      if (!cur) return null;
      if (cur.token !== r.token) throw new Refused("lease_lost", "only the holder of a lease can release it");
      return null;
    });
  }
}

// The receiver's withdrawn grants: the same table as Python's GrantStore. An unreadable store is Refused('unavailable'),
// never "not withdrawn".
export class GrantStore {
  constructor(path, { busyMs = 5000 } = {}) {
    this.path = path; this.busyMs = busyMs; mkParent(path);
    this._run("CREATE TABLE IF NOT EXISTS withdrawn (grant_id TEXT PRIMARY KEY, at INTEGER NOT NULL)");
  }
  _run(sql, ...args) {
    try {
      const db = new DatabaseSync(this.path, { timeout: this.busyMs });
      try { db.exec("PRAGMA synchronous=FULL"); return db.prepare(sql).all(...args); } finally { db.close(); }
    } catch (e) { throw new Refused("unavailable", `the grant store did not answer (${e && e.message})`); }
  }
  withdraw(grantId, now = Date.now()) { this._run("INSERT OR IGNORE INTO withdrawn VALUES (?, ?)", grantId, now); }
  isWithdrawn(grantId) { return this._run("SELECT 1 FROM withdrawn WHERE grant_id=?", grantId).length > 0; }
}

// ------------------------------------------------------------------------------------------------ the audit chain

const entryDigest = (e) => digest(e);

function lastDigestOf(path) {
  if (!existsSync(path)) return ZERO;
  return verifyAudit(path);
}

// Checks the chain and returns the last digest (64 zeros if empty). Refused('unavailable') if any entry was edited,
// removed from the middle or reordered, or the last line is partial.
export function verifyAudit(path) {
  if (!existsSync(path)) return ZERO;
  const raw = readFileSync(path);
  if (raw.length && raw[raw.length - 1] !== 0x0a) throw new Refused("unavailable", "the audit record ends in a partial entry");
  let last = ZERO, n = 0;
  for (const line of raw.toString("utf8").split("\n")) {
    if (!line) continue;
    n += 1;
    let claimed;
    try {
      const e = strictParse(line);
      claimed = e.digest; delete e.digest;
      if (e.prev !== last || entryDigest(e) !== claimed) throw new Error("chain broken");
    } catch { throw new Refused("unavailable", `the audit record is damaged at entry ${n}`); }
    last = claimed;
  }
  return last;
}

// Serialises writers on this host with an exclusive lock file. A lock a crashed process left behind is NOT broken
// automatically: the write refuses (nothing is permitted) until an operator removes it, which is the safe direction.
function withLock(path, fn, { waitMs = 5000 } = {}) {
  const lock = path + ".lock", end = Date.now() + waitMs;
  let fd = null;
  for (;;) {
    try { fd = openSync(lock, "wx"); break; } catch (e) {
      if (e.code !== "EEXIST") throw new Refused("unavailable", `the audit lock could not be taken (${e.code})`);
      if (Date.now() >= end) throw new Refused("unavailable", "the audit record is locked and the lock did not clear, so nothing is permitted");
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
    }
  }
  try { return fn(); } finally { closeSync(fd); try { unlinkSync(lock); } catch { /* already gone */ } }
}

// ------------------------------------------------------------------------------------------------ grants and approvals

const sorted = (xs) => [...xs].sort();
export class Grant {
  constructor({ id, capability, version, requester, deciders, actions, disclose_max = [], expires_at = null, approvers = [], retain_ms = 0 }) {
    if (!id || !capability || !actions?.length || !deciders?.length) throw new Error("a grant names an id, a capability, at least one decider and at least one action");
    if (!isAgentId(requester) || ![...deciders, ...approvers].every(isAgentId)) throw new Error("requester, deciders and approvers are agent identities");
    if (approvers.some((a) => deciders.includes(a) || a === requester)) throw new Error("an approver is never the decider or the requester: a party cannot approve itself");
    if (!isInt(version) || version < 1) throw new Error("version is a positive integer");
    Object.assign(this, { id, capability, version, requester, retain_ms, expires_at,
      deciders: new Set(deciders), actions: new Set(actions), disclose_max: new Set(disclose_max), approvers: new Set(approvers) });
    Object.freeze(this);
  }
}

// Read a receiver's grants from its own file, as strictly as a wire message. A typo can never become a wider grant.
export function loadGrants(text) {
  let doc;
  try { doc = strictParse(text); } catch (e) { throw new Error(`the grants file is not strict JSON (${e.code ?? "profile"})`); }
  if (!doc || Object.keys(doc).join() !== "grants" || !Array.isArray(doc.grants)) throw new Error('the grants file is exactly {"grants": [...]}');
  const required = ["id", "capability", "version", "requester", "deciders", "actions"];
  const allowed = new Set([...required, "disclose_max", "expires_at", "approvers", "retain_ms"]);
  return doc.grants.map((g) => {
    const keys = g && typeof g === "object" ? Object.keys(g) : [];
    if (!required.every((k) => keys.includes(k)) || !keys.every((k) => allowed.has(k))) throw new Error("a grant has " + required.join(", ") + " and optionally the rest");
    for (const l of ["deciders", "actions", "disclose_max", "approvers"]) {
      if (l in g && (!Array.isArray(g[l]) || !g[l].every((x) => typeof x === "string"))) throw new Error(`${l} is a list of text`);
    }
    return new Grant(g);
  });
}

const approvalBody = (a) => ({ approver: a.approver, decision_id: a.decision_id, action: a.action, subject_digest: a.subject_digest, expires_at: a.expires_at });
const approvalInput = (a) => Buffer.concat([APPROVAL_TAG, Buffer.from(digest(approvalBody(a)), "ascii")]);

// What a person's tool calls after reading what the decision and the action are.
export function approve(signer, verified, action, { ttlMs = 300000, now = Date.now() } = {}) {
  const a = { approver: signer.agent, decision_id: verified.envelope.id, action, subject_digest: verified.subject.digest, expires_at: now + ttlMs };
  return { ...a, sig: Buffer.from(signer.sign(approvalInput(a))).toString("hex") };
}

export class Permit {
  constructor(fields, ledger, reservation) { Object.assign(this, fields); Object.defineProperty(this, "_l", { value: { ledger, reservation } }); }
  complete() { this._finish(true); }
  abort() { this._finish(false); }
  _finish(commit) {
    const { ledger, reservation } = this._l;
    if (!reservation) throw new Error("this permit holds no lease");
    try { commit ? ledger.commit(reservation) : ledger.release(reservation); } catch (e) {
      if (e instanceof Refused) throw e;
      throw new Refused("unavailable", `the permit ledger did not confirm the ${commit ? "commit" : "release"} (${e && e.name})`);
    }
  }
}

export class GrantTable {
  constructor(grants = [], { auditPath = null, auditSink = null, store = null, permitLedger, permitLeaseMs = 60000 } = {}) {
    this.grants = new Map();
    for (const g of grants) {
      const k = `${g.capability} ${g.version}`;
      if (this.grants.has(k)) throw new Error(`two grants for ${g.capability} version ${g.version}`);
      this.grants.set(k, g);
    }
    if (!permitLedger || typeof permitLedger.reserve !== "function") throw new Error("permitLedger needs reserve, commit and release");
    if (auditSink && auditPath) throw new Error("an audit record is a file or a shared sink, not both");
    Object.assign(this, { store, permits: permitLedger, leaseMs: permitLeaseMs, auditPath, sink: auditSink, withdrawn: new Set() });
    this.last = auditSink ? auditSink.verify() : auditPath ? lastDigestOf(auditPath) : ZERO;   // a damaged chain, local or shared, is refused here, before anything is permitted
    if (auditPath) mkParent(auditPath);
  }
  withdraw(id) { if (this.store) this.store.withdraw(id); else this.withdrawn.add(id); }
  _isWithdrawn(id) { return this.withdrawn.has(id) || (this.store ? this.store.isWithdrawn(id) : false); }
  _grantFor(cap, ver) {
    const g = typeof cap === "string" ? this.grants.get(`${cap} ${ver}`) : undefined;
    if (!g) throw new Refused("no_grant", "this receiver has granted nothing for that capability and version");
    return g;
  }
  // Before anything is disclosed: a grant, in force, naming this decider, whose ceiling covers every field asked for.
  checkTerms(terms, { now = Date.now() } = {}) {
    const g = this._grantFor(terms.capability, terms.version);
    if (this._isWithdrawn(g.id)) throw new Refused("withdrawn", "the permission for this purpose was withdrawn");
    if (g.expires_at !== null && now >= g.expires_at) throw new Refused("grant_expired", "the permission for this purpose has expired");
    if (terms.requester !== g.requester) throw new Refused("no_grant", "the grant is for a different requester than the terms name");
    if (!g.deciders.has(terms.decider)) throw new Refused("decider", "this grant does not name that decider");
    const extra = (terms.disclose ?? []).filter((f) => !g.disclose_max.has(f));
    if (extra.length) throw new Refused("disclosure", "the terms ask to see fields this receiver will not disclose for this purpose: " + sorted(extra).join(", "));
    return g;
  }
  permit(action, verified, terms, { approval = null, now = Date.now() } = {}) {
    let approver = "", reservation = null, g = null;
    try {
      if (!terms || typeof terms !== "object" || Array.isArray(terms) || Object.keys(terms).sort().join() !== TERMS_KEYS) throw new Refused("terms", "the terms are not complete UAI-1 terms");
      if (!verified.allowed) throw new Refused("refused", "a decision that is not a pass permits nothing");
      if (termsDigest(terms) !== verified.envelope.body.terms_digest) throw new Refused("terms", "these are not the terms the decision was made under");
      g = this.checkTerms(terms, { now });
      if (verified.envelope.from !== terms.decider || digest(verified.subject) !== digest(terms.subject)) throw new Refused("terms", "the verified decision is not the one the terms describe");
      if (!g.actions.has(action)) throw new Refused("action", `this grant does not permit ${JSON.stringify(action)}`);
      if (g.approvers.size) approver = this._checkApproval(g, approval, verified, action, now);
      reservation = this._reserve(g, verified, action, now);
    } catch (e) {
      if (e instanceof Refused) this._record(now, action, terms, verified, approver, e.code, "");
      throw e;
    }
    let audit;
    try { audit = this._record(now, action, terms, verified, approver, "permitted", g.id); } catch (e) {
      try { this.permits.release(reservation); } catch { /* the lease lapses by itself */ }
      throw e;
    }
    return new Permit({ grant: g.id, action, capability: g.capability, version: g.version, decision_id: verified.envelope.id,
      subject_digest: verified.subject.digest, approver, audit_digest: audit, terms_digest: verified.envelope.body.terms_digest,
      idempotency_key: reservation.key }, this.permits, reservation);
  }
  _reserve(g, verified, action, now) {
    try { return this.permits.reserve(`permit:${g.id}`, `${verified.envelope.id}:${action}`, verified.envelope.expires_at, { leaseMs: this.leaseMs, now }); } catch (e) {
      if (e instanceof Refused) { if (e.code === "replayed") throw new Refused("replayed", "this decision already produced a permit for this action"); throw e; }
      throw new Refused("unavailable", `the permit ledger gave no answer (${e && e.name})`);
    }
  }
  _checkApproval(g, a, verified, action, now) {
    if (!a) throw new Refused("approval_required", "this action needs a person's approval and none was given");
    if (!g.approvers.has(a.approver)) throw new Refused("approval", "the approver is not one this grant names");
    if (a.approver === verified.envelope.from || a.approver === g.requester) throw new Refused("approval", "a party cannot approve its own action");
    if (a.decision_id !== verified.envelope.id || a.action !== action || a.subject_digest !== verified.subject.digest) throw new Refused("approval", "the approval is for a different decision, action or document");
    if (!isInt(a.expires_at) || !(a.expires_at > 0 && a.expires_at <= MAX_INT) || now >= a.expires_at) throw new Refused("approval", "the approval has expired");
    if (typeof a.sig !== "string" || !verifySig(a.approver, approvalInput(a), a.sig)) throw new Refused("approval", "the approval's signature does not verify as the approver");
    return a.approver;
  }
  _record(now, action, terms, verified, approver, outcome, grant) {
    const t = terms && typeof terms === "object" && !Array.isArray(terms) ? terms : {};
    const g = [...this.grants.values()].find((x) => x.id === grant);
    const entry = { at: now, action, outcome, grant, capability: String(t.capability), version: isInt(t.version) ? t.version : 0,
      decider: String(t.decider), requester: String(t.requester), decision_id: verified.envelope.id,
      subject_digest: verified.subject?.digest ?? "", approver, terms_digest: verified.envelope.body.terms_digest, retain_ms: g ? g.retain_ms : 0 };
    if (this.sink) { this.last = this.sink.append(entry); return this.last; }   // one chain across every host; Refused('unavailable') on failure
    if (!this.auditPath) { entry.prev = this.last; this.last = entryDigest(entry); return this.last; }
    this.last = appendAudit(this.auditPath, entry);
    return this.last;
  }
}

// Append one entry to a hash-chained audit file, under its lock, chained onto the REAL last entry; returns its digest. The
// GrantTable writes every permit and refusal this way; a receiver uses it directly for a record that is not a permit
// decision, such as a start-up refusal (clock_skew, unavailable, config), so a refusal to act leaves evidence in the same
// chain (RACE-02 I-07b). Refused('unavailable') when the file cannot be written. As Python's grants.append_audit.
export function appendAudit(path, entry) {
  return withLock(path, () => {
    try {
      entry.prev = lastDigestOf(path);       // the REAL last entry, read under the lock
      const d = entryDigest(entry);
      const fd = openSync(path, "a");
      try { writeSync(fd, JSON.stringify({ ...entry, digest: d }) + "\n"); fsyncSync(fd); } finally { closeSync(fd); }
      return d;
    } catch (e) {
      if (e instanceof Refused) throw e;
      throw new Refused("unavailable", `the audit record could not be written, so nothing is permitted (${e && e.code})`);
    }
  });
}
