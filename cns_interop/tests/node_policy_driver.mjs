// Test driver: run a list of policy and fencing operations against interop/node/pg_policy.mjs and fencing.mjs, one JSON result
// per operation. stdin: {"dsn_env": name, "prefix": p, "ops": [[op, ...args], ...]}. The DSN comes from the named environment
// variable, never from the command line.
import { readFileSync } from "node:fs";
import * as U from "../../interop/node/uai.mjs";
import * as G from "../../interop/node/grants.mjs";
import * as F from "../../interop/node/fencing.mjs";
import * as PP from "../../interop/node/pg_policy.mjs";

const job = JSON.parse(readFileSync(0, "utf8"));
const out = [];
const dsn = process.env[job.dsn_env] ?? "";
let store;
try { store = new PP.PostgresGrantStore(dsn, { prefix: job.prefix + "_policy" }); }
catch (e) { console.log(JSON.stringify([{ code: e.code ?? "config", reason: e.reason ?? e.message }])); process.exit(0); }
const target = new F.FencedTarget();
let audit = null;
const auditor = () => (audit ??= new PP.PostgresAudit(dsn, { prefix: job.prefix + "_audit" }));
const stubLedger = { reserve() { return { key: "k" }; }, commit() {}, release() {} };
for (const [op, ...a] of job.ops) {
  try {
    if (op === "withdraw") { store.withdraw(a[0]); out.push({ ok: true }); }
    else if (op === "is_withdrawn") out.push({ ok: store.isWithdrawn(a[0]) });
    else if (op === "check_terms") {   // [grants document, terms]: the receiver's grant check against the shared store
      const table = new G.GrantTable(G.loadGrants(JSON.stringify(a[0])), { store, permitLedger: stubLedger });
      out.push({ ok: table.checkTerms(a[1]).id });
    }
    else if (op === "fence") { target.check(a[0], a[1]); out.push({ ok: true }); }
    else if (op === "policy_digest") out.push({ ok: PP.policyDigest(G.loadGrants(JSON.stringify(a[0]))) });
    else if (op === "publish") { store.publishPolicy(a[0], a[1]); out.push({ ok: true }); }
    else if (op === "current") out.push({ ok: store.currentPolicy() });
    else if (op === "require") out.push({ ok: store.requirePolicy(a[0]) });
    else if (op === "audit_append") out.push({ ok: auditor().append(a[0]) });
    else if (op === "audit_verify") out.push({ ok: auditor().verify() });
    else if (op === "audit_head") out.push({ ok: auditor().head() });
    else throw new Error(`unknown op ${op}`);
  } catch (e) { out.push({ code: e instanceof U.Refused ? e.code : e instanceof RangeError ? "caller_error" : "error", reason: e.reason ?? e.message }); }
}
console.log(JSON.stringify(out));
