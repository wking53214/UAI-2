// One ledger operation against interop/node/pg.mjs per process, for the conformance properties (Python drives it).
// stdin: {"dsn_env": name, "table": t, "op": "spend"|"reserve"|"commit"|"release", "a": {...}}. The DSN comes from the
// named environment variable. Caller time is allowed because the generic properties drive time with now=.
import { readFileSync } from "node:fs";
import * as P from "../../interop/node/pg.mjs";

const job = JSON.parse(readFileSync(0, "utf8"));
const a = job.a ?? {};
let out;
try {
  const L = new P.PostgresLedger(process.env[job.dsn_env] ?? "", { table: job.table, allowCallerTime: true });
  if (job.op === "spend") { L.spend(a.sender, a.id, a.expires_at ?? null, { now: a.now }); out = { ok: true }; }
  else if (job.op === "reserve") {
    const r = L.reserve(a.sender, a.id, a.expires_at ?? null, { leaseMs: a.lease_ms, now: a.now });
    out = { ok: { token: r.token, lease_until: r.leaseUntil, fence: r.fence } };
  } else if (job.op === "commit") { L.commit(a.reservation); out = { ok: true }; }
  else if (job.op === "release") { L.release(a.reservation); out = { ok: true }; }
  else throw new Error(`unknown op ${job.op}`);
} catch (e) {
  out = e instanceof RangeError ? { caller_error: e.message } : { code: e.code ?? "error", reason: e.reason ?? e.message };
}
console.log(JSON.stringify(out));
