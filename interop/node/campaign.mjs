// campaign (Node side): runs contracts/uai-interop-vectors.json through uai.mjs and prints, per case, what it did.
// The Python side is interop/campaign.py. Neither reads an expectation; the pytest comparison does.
//   node interop/node/campaign.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as U from "./uai.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const V = JSON.parse(readFileSync(root + "contracts/uai-interop-vectors.json", "utf8"));
const code = (e) => (e instanceof U.Refused ? e.code : `internal:${e && e.name}`);

function bytesOf(c) {
  if (c.generate === "exact_mib") return Buffer.from('{"a":"' + "x".repeat((1 << 20) - 8) + '"}');
  if (c.generate === "over_mib") return Buffer.from('{"a":"' + "x".repeat((1 << 20) - 7) + '"}');
  return Buffer.from(c.b64, "base64");
}
const ok = (extra = {}) => ({ outcome: "ok", ...extra });
const no = (e) => ({ outcome: "refuse", code: code(e) });

const run = {
  digest(c) {
    try { const v = U.strictParseBytes(Buffer.from(c.text, "utf8")); U.checkProfile(v); return ok({ canonical: U.canonical(v), sha256: U.digest(v) }); }
    catch (e) { return no(e); }
  },
  wire(c) { try { U.strictParseBytes(bytesOf(c)); return ok(); } catch (e) { return no(e); } },
  envelope(c) {
    try { const w = U.strictParseBytes(Buffer.from(c.text, "utf8")); U.openEnvelope(w, { now: c.now, audience: c.audience, kinds: c.kinds ? new Set(c.kinds) : null }); return ok(); }
    catch (e) { return no(e); }
  },
  negotiation(c) {
    try { return ok({ terms: U.proposeTerms(c.capability, c.request, { decider: c.decider, requester: c.requester }) }); }
    catch (e) { return no(e); }
  },
  sequences(c) {
    const cfg = c.config, store = new U.RevocationStore(), ledger = new U.Ledger();
    const trust = new U.PinnedTrust(cfg.pinned, [], { revocations: store, maxStalenessMs: cfg.max_staleness_ms, followRotation: cfg.follow_rotation });
    const steps = [];
    for (const s of c.steps) {
      try {
        if (s.op === "receive") {
          const env = U.openEnvelope(U.strictParseBytes(Buffer.from(s.text, "utf8")), { now: s.now, audience: cfg.self, kinds: new Set(["request"]) });
          trust.admit(env.from, { now: s.now });
          ledger.spend(env.from, env.id, env.expires_at, { now: s.now });
        } else if (s.op === "revocation") store.accept(U.strictParseBytes(Buffer.from(s.text, "utf8")), { authorities: cfg.authorities, now: s.now });
        else if (s.op === "fresh") store.markFresh(s.now);
        steps.push("ok");
      } catch (e) { steps.push(code(e)); }
    }
    return { steps };
  },
  decisions(c) {
    const cfg = c.config, ledger = new U.Ledger(); let now = 0;
    const mk = () => new U.RemoteDecisionGuard((a) => a, { actingFor: cfg.acting_for, capability: cfg.capability, trust: new U.PinnedTrust(cfg.pinned), ledger, clock: () => now });
    let guard = mk(); const steps = [];
    for (const s of c.steps) {
      if (s.now !== undefined) now = s.now;
      try {
        if (s.op === "authorize") { guard.authorize(s.decision, { terms: s.terms, acceptDigest: s.accept_digest, leaseMs: s.lease_ms }); steps.push("ok"); }
        else if (s.op === "use") steps.push(guard.call(s.artifact) ? "true" : "false");
        else if (s.op === "new_guard") { guard = mk(); steps.push("ok"); }
        else if (s.op === "revoke_decider") { guard.revoke(cfg.pinned[0]); steps.push("ok"); }
        else if (s.op === "complete") { guard.complete(); steps.push("ok"); }
      } catch (e) { steps.push(code(e)); }
    }
    return { steps };
  },
};

const out = {};
for (const g of Object.keys(run)) for (const c of V[g]) out[c.id] = run[g](c);
console.log(JSON.stringify(out));
