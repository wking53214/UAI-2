// pg_policy.mjs: the receiver's policy state in PostgreSQL, the Node twin of cns_interop/policy_postgres.py, over the same
// tables, so a Python and a Node receiver on different hosts share them. This is the RECEIVER's storage: CNS holds no
// authority here. Like pg.mjs it talks to PostgreSQL through the `psql` client (no npm dependency), and every answer that is
// not definite is Refused('unavailable'), never "not withdrawn".
//   * WITHDRAWALS (PostgresGrantStore): `<prefix>_withdrawn (grant_id text PRIMARY KEY, at bigint)`, the same `withdraw` /
//     `isWithdrawn` as grants.GrantStore, so a GrantTable takes it as its `store`. The withdrawal time is the DATABASE's.
//   * THE POLICY VERSION (PostgresGrantStore.publishPolicy / currentPolicy / requirePolicy, and policyDigest): each host loads
//     its grants from its own file; policyDigest fingerprints what a host loaded (the same digest as Python's policy_digest),
//     publishPolicy moves the shared version forward by exactly one under an advisory lock (two operators publishing the same
//     version cannot both win: the loser is 'conflict'), and requirePolicy makes a host whose grants differ from the published
//     ones ('stale_policy') or find none refuse to act. An unreachable database is 'unavailable', never a pass.
//   * THE AUDIT CHAIN (PostgresAudit): `<prefix>_chain (seq bigserial, digest text UNIQUE, entry text)`, the same chain as
//     Python's PostgresAudit. Each entry carries the digest of the one before (uai.mjs `digest` equals cns subject_digest, so a
//     chain either language wrote verifies in the other, and no historical hash changes). One writer at a time on any host: the
//     INSERT takes the same advisory lock Python takes and is conditional on the head still being the one the digest was
//     computed over, because the digest is computed here between two psql calls; a lost race is retried, never chained wrongly.
import { NAME, NOW_MS, PgGuard } from "./pg.mjs";
import { Refused, digest, strictParse } from "./uai.mjs";

const ZERO = "0".repeat(64);
const HEX = /^[0-9a-f]{64}$/;
const MAX_APPEND_TRIES = 64;
const HEAD = (t) => `COALESCE((SELECT digest FROM ${t} ORDER BY seq DESC LIMIT 1), :'zero')`;
// Python's json.dumps(x, sort_keys=True) for the plain data a grant holds (default separators, ensure_ascii), the key Python
// orders grants by. Needed only so the two languages order the rows of a policy digest identically.
function pyJson(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return String(v);
  if (typeof v === "string") {
    let o = '"';
    for (let i = 0; i < v.length; i++) {
      const c = v.charCodeAt(i), ch = v[i];
      if (ch === '"') o += '\\"'; else if (ch === "\\") o += "\\\\";
      else if (ch === "\n") o += "\\n"; else if (ch === "\r") o += "\\r"; else if (ch === "\t") o += "\\t";
      else if (ch === "\b") o += "\\b"; else if (ch === "\f") o += "\\f";
      else if (c < 0x20 || c > 0x7e) o += "\\u" + c.toString(16).padStart(4, "0");
      else o += ch;
    }
    return o + '"';
  }
  if (Array.isArray(v)) return "[" + v.map(pyJson).join(", ") + "]";
  return "{" + Object.keys(v).sort().map((k) => pyJson(k) + ": " + pyJson(v[k])).join(", ") + "}";
}

// A fingerprint of a set of grants, independent of their order, equal to Python's policy_digest for the same grants, so two
// hosts that loaded the same policy agree whatever language they run in.
export function policyDigest(grants) {
  const rows = [...grants].map((g) => ({ id: g.id, capability: g.capability, version: g.version, requester: g.requester,
    deciders: [...g.deciders].sort(), actions: [...g.actions].sort(), disclose_max: [...g.disclose_max].sort(),
    expires_at: g.expires_at, approvers: [...g.approvers].sort(), retain_ms: g.retain_ms }));
  rows.sort((a, b) => { const x = pyJson(a), y = pyJson(b); return x < y ? -1 : x > y ? 1 : 0; });
  return digest({ grants: rows });
}

// Sorted keys at every depth, as Python's json.dumps(sort_keys=True). Verification re-parses the text and re-derives the digest,
// so the exact bytes of an entry are not part of the contract; the parsed entry and its digest are.
const sortedJson = (v) => JSON.stringify(v, (_k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, x[k]])) : x));

export class PostgresGrantStore extends PgGuard {
  constructor(dsn, { prefix = "uai_policy", ...kw } = {}) {
    if (!NAME.test(prefix)) throw new RangeError("prefix is a lowercase SQL identifier");
    super(dsn, kw);
    this._w = prefix + "_withdrawn"; this._p = prefix + "_version";
    this._run(`SELECT pg_advisory_xact_lock(7243002);
CREATE TABLE IF NOT EXISTS ${this._w} (grant_id text PRIMARY KEY, at bigint NOT NULL);
CREATE TABLE IF NOT EXISTS ${this._p} (version bigint PRIMARY KEY, digest text NOT NULL, at bigint NOT NULL);`);
  }

  // Same surface as grants.GrantStore. A withdrawal committed here is seen by the next check on every host.
  withdraw(grantId) {
    this._run(`INSERT INTO ${this._w} VALUES (:'g', ${NOW_MS}) ON CONFLICT DO NOTHING;`, { g: grantId });
  }
  isWithdrawn(grantId) { return this._run(`SELECT 1 FROM ${this._w} WHERE grant_id = :'g';`, { g: grantId }).length > 0; }

  // The shared policy version: [version, digest], or [0, zeros] when nothing was ever published.
  currentPolicy() {
    const rows = this._run(`SELECT version, digest FROM ${this._p} ORDER BY version DESC LIMIT 1;`);
    return rows.length ? [Number(rows[0][0]), rows[0][1]] : [0, ZERO];
  }

  // Move the shared policy to `version`, which must be exactly the current version plus one; otherwise Refused('conflict'):
  // another operator published first, so re-read and decide again. Nothing here edits a grant. RangeError for a bad argument.
  publishPolicy(version, digestHex) {
    if (!Number.isSafeInteger(version) || version < 1 || typeof digestHex !== "string" || !HEX.test(digestHex)) throw new RangeError("a policy version is a positive integer and its digest is 64 hex characters");
    const rows = this._run(`SELECT pg_advisory_xact_lock(7243003);
INSERT INTO ${this._p} SELECT :'v'::bigint, :'d', ${NOW_MS} WHERE (SELECT COALESCE(max(version), 0) FROM ${this._p}) + 1 = :'v'::bigint RETURNING version;`, { v: version, d: digestHex });
    if (rows.length !== 1) throw new Refused("conflict", `policy version ${version} is not the next version; another operator published first`);
  }

  // The published version if this host's grants are exactly the published ones; otherwise Refused('stale_policy'): a host with
  // stale or divergent grants must not act, because it would permit what the others no longer do.
  requirePolicy(digestHex) {
    const [version, published] = this.currentPolicy();
    if (version === 0) throw new Refused("stale_policy", "no policy has been published to the shared store");
    if (published !== digestHex) throw new Refused("stale_policy", `this host's grants are not the published policy (version ${version})`);
    return version;
  }
}

export class PostgresAudit extends PgGuard {
  constructor(dsn, { prefix = "uai_audit", ...kw } = {}) {
    if (!NAME.test(prefix)) throw new RangeError("prefix is a lowercase SQL identifier");
    super(dsn, kw);
    this._t = prefix + "_chain";
    this._run(`SELECT pg_advisory_xact_lock(7243004);
CREATE TABLE IF NOT EXISTS ${this._t} (seq bigserial PRIMARY KEY, digest text NOT NULL UNIQUE, entry text NOT NULL);`);
  }

  // Append one entry; returns its digest. Refused('unavailable') when the database gives no definite answer.
  append(entry) {
    const T = this._t;
    for (let attempt = 0; attempt < MAX_APPEND_TRIES; attempt++) {
      const [[prev]] = this._run(`SELECT ${HEAD(T)};`, { zero: ZERO });
      const body = { ...entry, prev };
      const d = digest(body);
      const rows = this._run(`SELECT pg_advisory_xact_lock(hashtext('${T}'));
INSERT INTO ${T} (digest, entry) SELECT :'d', :'text' WHERE ${HEAD(T)} = :'prev' RETURNING 1;`,
      { d, text: sortedJson({ ...body, digest: d }), prev, zero: ZERO });
      if (rows.length === 1) return d;
    }
    throw new Refused("unavailable", "the audit chain kept changing under this writer, so the entry was not written");
  }

  head() { return this._run(`SELECT ${HEAD(this._t)};`, { zero: ZERO })[0][0]; }

  // Re-derive the whole chain and return the last digest; Refused('unavailable') if any entry was edited, removed from the
  // middle or reordered. In pages by seq, so a long chain does not need one huge answer.
  verify() {
    let last = ZERO, n = 0, after = "-9223372036854775807";
    for (;;) {
      const rows = this._run(`SELECT seq, digest, entry FROM ${this._t} WHERE seq > :'after'::bigint ORDER BY seq LIMIT 500;`, { after });
      if (rows.length === 0) return last;
      for (const row of rows) {
        n += 1;
        try {
          if (row.length !== 3) throw new Error("chain broken");
          const [seq, stored, text] = row;
          const e = strictParse(text);
          const claimed = e.digest; delete e.digest;
          if (e.prev !== last || digest(e) !== claimed || claimed !== stored) throw new Error("chain broken");
          last = claimed; after = seq;
        } catch (err) {
          if (err instanceof Refused && err.code === "unavailable") throw err;
          throw new Refused("unavailable", `the audit record is damaged at entry ${n}`);
        }
      }
    }
  }
}
