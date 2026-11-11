// act.mjs: the Node twin of interop/act.py. One job on stdin, the receiver's policy on the command line and in files, one
// JSON answer on stdout. It opens the SAME SQLite ledger and grant-store files as `act.py --ledger-backend sqlite`, so a
// decision spent or a grant withdrawn through either program is seen by the other. With `--ledger-backend postgres` it
// spends decisions and permits in the same PostgreSQL tables as `act.py --ledger-backend postgres` (`<prefix>_decisions`,
// `<prefix>_permits`), so receivers in either language on any number of hosts share one ledger. The DSN is read from the
// environment variable named by --ledger-dsn-env, never from the command line; with the local policy backend, withdrawals and the audit stay in local files. A signed decision is not permission:
// this program acts only under the receiver's grants (--decision-only is the explicit, loud exception).
//
//   node interop/node/act.mjs --acting-for <id> --capability <name> --capability-version <n> --trust <id>[,<id>]
//        --ledger <sqlite file> --grants <grants.json> --grant-store <sqlite file> --action <name> --audit <file>
//        [--permit-ledger <sqlite file>] [--lease-ms <ms>] | --decision-only
//   the shared backend: --ledger-backend postgres --ledger-dsn-env <ENV VAR> [--ledger-prefix <prefix>] in place of --ledger
//   [--policy-backend postgres [--publish-policy <next version>]]: withdrawals, the policy version and ONE hash-chained audit
//   record in the same database (pg_policy.mjs), exactly as act.py: --grant-store and --audit are then not given, a host whose
//   grants file is not the published policy refuses to start (stale_policy), --publish-policy publishes it and exits
//   [--require-sync-replication]: refuse (unavailable, exit 2) unless the server demands a synchronous standby, and commit only
//   once it confirms (pg.mjs requireSyncReplication), as act.py
//   [--max-clock-skew-ms <ms>]: compare this host's clock with the database's first, and refuse (exit 2, clock_skew) if
//   they differ by more; then judge every lifetime by the DATABASE's time carried on this host's monotonic clock
//   (pg.mjs TrustedClock), never by this host's wall clock. The tolerance must be strictly below the ledger's retention
//   window (120 s), or the start is refused as config. Without the flag (the development and test opt-out: UAI_PROFILE
//   unset) lifetimes are judged by this host's clock, and the PostgreSQL ledger still refuses a message expired by its own
//   clock.
//   UAI_PROFILE=production is enforced exactly as act.py enforces it, before any file or table is touched: the postgres
//   ledger (sqlite is refused as config, exit 2), --policy-backend postgres (host-local withdrawals and audit are refused as
//   config; only --decision-only can run without it), and --max-clock-skew-ms (required).

import { mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import * as U from "./uai.mjs";
import * as G from "./grants.mjs";
import * as P from "./pg.mjs";
import * as PP from "./pg_policy.mjs";

const refuse = (code, reason, status = 0) => { console.log(JSON.stringify({ refused: { code, reason } })); return status; };
const APPROVAL_KEYS = "action,approver,decision_id,expires_at,sig,subject_digest";
const FLAGS = new Set(["decision-only", "require-sync-replication"]);
const PRODUCTION = U.cryptoDiagnostics().profile === "production";   // UAI_PROFILE, read once, as in Python

// A refusal that is not a permit decision (config, clock_skew, unavailable): exit 2 at start-up, nothing verified or spent.
// AUDITED, as act.py's _audit_refusal (RACE-02 I-07b): appended to the --audit file where one is configured (Node has no
// shared audit chain), and ALWAYS written as one structured line on stderr, {"uai_audit": {...}}, which says whether it was
// recorded. A failure to record is reported there, never swallowed. `at` is this host's clock: the refusal may be about the
// database's. stage is "startup", or "decision" when the clock was re-read for the decision and failed.
function auditRefusal(cfg, code, reason, stage) {
  const version = Number(cfg["capability-version"]);
  const entry = { at: Date.now(), outcome: code, stage, reason, action: cfg.action ?? "", capability: String(cfg.capability ?? ""),
    version: Number.isSafeInteger(version) ? version : 0, requester: String(cfg["acting-for"] ?? ""), decider: "", decision_id: "",
    subject_digest: "", approver: "", terms_digest: "", grant: "", retain_ms: 0, profile: PRODUCTION ? "production" : "default" };
  let recorded = null, note = "";
  try {
    if (cfg["policy-backend"] === "postgres" && (cfg["ledger-backend"] ?? "sqlite") === "postgres" && cfg["ledger-dsn-env"]) {
      const dsn = process.env[cfg["ledger-dsn-env"]] ?? "";
      if (dsn) { new PP.PostgresAudit(dsn, { prefix: (cfg["ledger-prefix"] ?? "uai") + "_audit", requireSyncReplication: cfg["require-sync-replication"] === true }).append({ ...entry }); recorded = "postgres"; }
    } else if (cfg.audit) { mkdirSync(dirname(cfg.audit), { recursive: true }); G.appendAudit(cfg.audit, { ...entry }); recorded = "file"; }
  }
  catch (e) { note = `${e && e.name}: ${e && e.message}`; }
  console.error(JSON.stringify({ uai_audit: { ...entry, recorded, audit_error: note } }));
}
function refuseStartup(cfg, code, reason) { auditRefusal(cfg, code, reason, "startup"); return refuse(code, reason, 2); }
// A trusted clock whose per-decision re-read, if it refuses, is audited before the refusal propagates.
function auditedClock(cfg, trusted) {
  const f = trusted.asClock();
  const sync = f.sync;
  f.sync = () => { try { return sync(); } catch (e) { if (e instanceof U.Refused) auditRefusal(cfg, e.code, e.reason, "decision"); throw e; } };
  return f;
}

function parse(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) throw new Error(`unexpected argument ${a}`);
    const k = a.slice(2);
    if (FLAGS.has(k)) o[k] = true; else { if (i + 1 >= argv.length) throw new Error(`--${k} needs a value`); o[k] = argv[++i]; }
  }
  return o;
}

function main() {
  let cfg;
  try { cfg = parse(process.argv.slice(2)); } catch (e) { return refuse("config", e.message, 2); }
  for (const k of ["acting-for", "capability", "capability-version", "trust"]) if (!cfg[k]) return refuse("config", `--${k} is required`, 2);
  const backend = cfg["ledger-backend"] ?? "sqlite";
  const sync = cfg["require-sync-replication"] === true;   // quorum-durable commits: refuse unless the server demands a synchronous standby
  let ledgerFor, dsn = "", prefix = "uai";
  if (backend === "postgres") {
    if (cfg.ledger || cfg["permit-ledger"]) return refuseStartup(cfg, "config", "--ledger and --permit-ledger name files; the postgres backend takes only --ledger-dsn-env");
    if (!cfg["ledger-dsn-env"]) return refuseStartup(cfg, "config", "--ledger-backend postgres needs --ledger-dsn-env, the name of the variable holding the DSN");
    dsn = process.env[cfg["ledger-dsn-env"]] ?? "";
    if (!dsn) return refuseStartup(cfg, "config", `the environment variable ${cfg["ledger-dsn-env"]} is not set; there is no fallback to a file ledger`);
    prefix = cfg["ledger-prefix"] ?? "uai";
    ledgerFor = (kind) => new P.PostgresLedger(dsn, { table: `${prefix}_${kind}`, requireSyncReplication: sync });
  } else if (backend === "sqlite") {
    if (!cfg.ledger) return refuseStartup(cfg, "config", "--ledger is required");
    if (cfg["ledger-dsn-env"] || cfg["ledger-prefix"] || sync) return refuseStartup(cfg, "config", "--ledger-dsn-env, --ledger-prefix and --require-sync-replication belong to the postgres backend");
    ledgerFor = (kind) => new G.SqliteLedger(kind === "decisions" ? cfg.ledger : (cfg["permit-ledger"] ?? cfg.ledger + ".permits"));
  } else return refuseStartup(cfg, "config", "--ledger-backend is sqlite or postgres");
  const maxSkew = cfg["max-clock-skew-ms"] === undefined ? null : Number(cfg["max-clock-skew-ms"]);
  if (maxSkew !== null && (backend !== "postgres" || !Number.isSafeInteger(maxSkew) || maxSkew < 0)) return refuseStartup(cfg, "config", "--max-clock-skew-ms is a non-negative number of ms, for the postgres backend");
  const policyBackend = cfg["policy-backend"] ?? "local";
  if (policyBackend !== "local" && policyBackend !== "postgres") return refuseStartup(cfg, "config", "--policy-backend is local or postgres");
  const shared = policyBackend === "postgres";   // withdrawals, the policy version and ONE audit chain in PostgreSQL, as act.py
  if (shared && (cfg["grant-store"] || cfg.audit)) return refuseStartup(cfg, "config", "--policy-backend postgres keeps withdrawals and the audit record in the database; do not give --grant-store or --audit");
  if (shared && backend !== "postgres") return refuseStartup(cfg, "config", "--policy-backend postgres needs --ledger-backend postgres (one database, one DSN variable)");
  if (cfg["publish-policy"] !== undefined && !shared) return refuseStartup(cfg, "config", "--publish-policy belongs to --policy-backend postgres");
  // The production profile, exactly as act.py applies it: the shared ledger, the shared policy store (or --decision-only,
  // which has no policy), and the clock check, all before any state is created.
  if (PRODUCTION) {
    if (backend !== "postgres") return refuseStartup(cfg, "config", "the production profile does not accept a single-host ledger; use --ledger-backend postgres");
    if (!shared && !cfg["decision-only"]) return refuseStartup(cfg, "config", "the production profile does not accept host-local withdrawals and audit; use --policy-backend postgres");
    if (maxSkew === null) return refuseStartup(cfg, "config", "the production profile judges message lifetimes by the ledger database's clock: give --max-clock-skew-ms (strictly below the ledger's 120000 ms retention window)");
  }
  const policy = (shared ? ["grants", "action"] : ["grants", "grant-store", "action", "audit"]).map((k) => cfg[k]);
  if (cfg["decision-only"]) {
    if (policy.some(Boolean) || cfg["permit-ledger"]) return refuseStartup(cfg, "config", "--decision-only cannot be combined with receiver policy options");
    console.error("act.mjs: --decision-only: a signed decision opens this action by itself; it is NOT receiver-authorized");
  } else if (!policy.every(Boolean)) {
    return refuseStartup(cfg, "config", "act.mjs acts only under the receiver's policy: give --grants, --grant-store, --action and --audit (with --policy-backend postgres: --grants and --action), or --decision-only to accept that a signature alone opens the action");
  }
  // The decision ledger and the clock check come first: a refusal here leaves no grant store, permit ledger or job behind.
  let decisions, clock = Date.now;   // this host's clock, unless the receiver asked for the database's
  try {
    decisions = ledgerFor("decisions");
    if (maxSkew !== null) { const trusted = new P.TrustedClock(decisions, maxSkew, { keepMs: decisions.keepMs }); trusted.sync(); clock = auditedClock(cfg, trusted); }
  } catch (e) { return e instanceof U.Refused ? refuseStartup(cfg, e.code, e.reason) : refuseStartup(cfg, "config", e.message); }
  const stdin = readFileSync(0);
  let guard;
  try {
    let table = null;
    if (!cfg["decision-only"]) {
      const loaded = G.loadGrants(readFileSync(cfg.grants, "utf8"));
      let store, sink = null;
      if (shared) {
        store = new PP.PostgresGrantStore(dsn, { prefix: prefix + "_policy", requireSyncReplication: sync }); sink = new PP.PostgresAudit(dsn, { prefix: prefix + "_audit", requireSyncReplication: sync });
        if (cfg["publish-policy"] !== undefined) {
          const version = Number(cfg["publish-policy"]);
          store.publishPolicy(version, PP.policyDigest(loaded));
          console.log(JSON.stringify({ published: { version, digest: PP.policyDigest(loaded) } }));
          return 0;
        }
        store.requirePolicy(PP.policyDigest(loaded));   // stale or divergent grants: this host does not act
      } else store = new G.GrantStore(cfg["grant-store"]);
      table = new G.GrantTable(loaded, {
        auditPath: shared ? null : cfg.audit, auditSink: sink, store,
        permitLedger: ledgerFor("permits"), permitLeaseMs: Number(cfg["lease-ms"] ?? 30000) });
    }
    guard = new U.RemoteDecisionGuard((a) => { if (!Array.isArray(a) || a.length !== 2 || !a.every((x) => typeof x === "string")) throw new Error("an artifact here is [identity, digest]"); return a; }, {
      actingFor: cfg["acting-for"], capability: [cfg.capability, Number(cfg["capability-version"])],
      trust: new U.PinnedTrust(cfg.trust.split(",").filter(Boolean)), ledger: decisions, clock,
      grants: table, action: cfg["decision-only"] ? null : cfg.action });
  } catch (e) { return e instanceof U.Refused ? refuseStartup(cfg, e.code, e.reason) : refuseStartup(cfg, "config", e.message); }
  let job;
  try {
    job = U.strictParseBytes(stdin);
    const keys = Object.keys(job ?? {}).sort().join();
    if (!["accept_digest,artifact,decision,terms", "accept_digest,approval,artifact,decision,terms"].includes(keys)) throw new U.Refused("malformed", "a job is exactly decision, terms, accept_digest, artifact and optionally approval");
    let approval = null;
    if ("approval" in job) {
      if (!job.approval || typeof job.approval !== "object" || Object.keys(job.approval).sort().join() !== APPROVAL_KEYS) throw new U.Refused("approval", "an approval is exactly " + APPROVAL_KEYS.split(",").join(", "));
      approval = job.approval;
    }
    guard.authorize(job.decision, { terms: job.terms, acceptDigest: job.accept_digest, leaseMs: cfg["decision-only"] ? null : Number(cfg["lease-ms"] ?? 30000), approval });
  } catch (e) { return e instanceof U.Refused ? refuse(e.code, e.reason) : refuse("malformed", String(e.message)); }
  const permitted = guard.call(job.artifact);
  const result = { permitted };
  if (!cfg["decision-only"]) {
    try {
      if (permitted) { guard.complete(); const p = guard.permit; result.permit = { grant: p.grant, action: p.action, audit_digest: p.audit_digest, idempotency_key: p.idempotency_key }; } else guard.abort();
    } catch (e) { return e instanceof U.Refused ? refuse(e.code, e.reason) : refuse("unavailable", String(e.message)); }
  }
  console.log(JSON.stringify(result));
  return 0;
}
process.exitCode = main();
