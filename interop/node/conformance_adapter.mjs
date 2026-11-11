// The Node side of the UAI-1 conformance protocol (see contracts/uai1/README.md and interop/conformance/reference_adapter.py).
import { createInterface } from "node:readline";
import * as U from "./uai.mjs";

let ledger = new U.Ledger();
const rl = createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const req = JSON.parse(line);
  let out;
  if (req.op === "reset") { ledger = new U.Ledger(); out = { ok: true }; } else {
    try {
      const wire = U.strictParse(req.wire_text);
      const env = U.openEnvelope(wire, { now: req.now, audience: req.audience, kinds: req.kinds ? new Set(req.kinds) : null });
      if (req.trust !== null && !req.trust.includes(env.from)) throw new U.Refused("untrusted", "the signer is not one this receiver admits");
      if (req.ledger) ledger.spend(env.from, env.id, env.expires_at, { now: req.now });
      out = { accept: { digest: U.envelopeDigest(wire) } };
    } catch (e) {
      out = { refuse: e instanceof U.Refused ? e.code : "internal:" + e.message };
    }
  }
  console.log(JSON.stringify(out));
});
