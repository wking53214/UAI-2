// The Node decider agent driven over its pipe, for the rules that live in agent.mjs rather than uai.mjs.
// Regressions for the 2026-10-30 independent review: a lapsed offer and an over-full accept were both accepted.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import * as U from "./uai.mjs";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const skewFile = join(mkdtempSync(join(tmpdir(), "uai-")), "skew");
const D = U.signerFromSeed(Buffer.alloc(32, 7)), R = U.signerFromSeed(Buffer.alloc(32, 8));

function startDecider() {
  writeFileSync(skewFile, "0");
  const p = spawn(process.execPath, ["--import", here("./testclock.mjs"), here("./agent.mjs"), "decider"],
    { env: { ...process.env, UAI_SEED: Buffer.alloc(32, 7).toString("hex"), UAI_TRUST: R.agent, UAI_TEST_SKEW_FILE: skewFile } });
  let buf = ""; const lines = [], waiters = [];
  p.stdout.on("data", (d) => {
    buf += d; let k;
    while ((k = buf.indexOf("\n")) >= 0) { const l = JSON.parse(buf.slice(0, k)); buf = buf.slice(k + 1); (waiters.shift() || ((x) => lines.push(x)))(l); }
  });
  const next = () => (lines.length ? Promise.resolve(lines.shift()) : new Promise((r) => waiters.push(r)));
  return { next, send: (o) => p.stdin.write(JSON.stringify(o) + "\n"), raw: (b) => p.stdin.write(b), stop: () => p.kill() };
}

async function exchange(agent, { extra = {}, skew = 0 }) {
  writeFileSync(skewFile, "0");
  const doc = U.commit("loan-1", { doc_type: "paystub", monthly_income_cents: 500000, ssn: "123-45-6789" });
  const req = U.requestBody("income-screen", 1, { identity: doc.identity, digest: doc.digest, offerFields: ["doc_type", "monthly_income_cents"], requireEvidence: ["threshold-check"], maxTtlMs: 600000 });
  agent.send(U.seal(R, "request", req, { to: D.agent, ttlMs: 60000 }));
  const offer = await agent.next();
  writeFileSync(skewFile, String(skew));
  const t = offer.body.terms;
  agent.send(U.seal(R, "accept", { terms_digest: U.termsDigest(t), disclosure: doc.reveal(t.disclose), ...extra }, { to: D.agent, replyTo: offer, ttlMs: 60000, now: Date.now() + skew }));
  return agent.next();
}

test("the Node decider decides a proper exchange, refuses a lapsed offer and an over-full accept", async () => {
  const agent = startDecider();
  try {
    assert.equal((await agent.next()).kind, "manifest");
    const ok = await exchange(agent, {});
    assert.equal(ok.kind, "decision"); assert.equal(ok.body.verdict, "pass");
    const lapsed = await exchange(agent, { skew: 600000 });
    assert.equal(lapsed.uai_error?.code, "expired");
    const leaky = await exchange(agent, { extra: { ssn: "123-45-6789" } });
    assert.equal(leaky.kind, "refuse"); assert.equal(leaky.body.code, "terms");
  } finally { agent.stop(); }
});

test("the Node decider spends no signature check on an unadmitted sender, signs nothing for it, and remembers nothing about it", async () => {
  const agent = startDecider();
  try {
    assert.equal((await agent.next()).kind, "manifest");
    const stranger = U.signerFromSeed(Buffer.alloc(32, 99));
    const doc = U.commit("loan-x", { doc_type: "paystub", monthly_income_cents: 500000 });
    const body = U.requestBody("income-screen", 1, { identity: doc.identity, digest: doc.digest, offerFields: ["doc_type", "monthly_income_cents"], requireEvidence: ["threshold-check"], maxTtlMs: 600000 });
    const request = U.seal(stranger, "request", body, { to: D.agent, ttlMs: 60000 });
    for (let i = 0; i < 2; i++) {            // the same bytes twice: the same unsigned error, never a "replayed" and never a signed refusal
      agent.send(request);
      const out = await agent.next();
      assert.equal(out.uai_error?.code, "untrusted"); assert.equal(out.kind, undefined); assert.equal(out.sig, undefined);
    }
  } finally { agent.stop(); }
});

test("the Node agent refuses invalid UTF-8 and an endless line instead of decoding leniently or buffering without limit", async () => {
  const agent = startDecider();
  try {
    assert.equal((await agent.next()).kind, "manifest");
    agent.raw(Buffer.concat([Buffer.from('{"a":"'), Buffer.from([0xff]), Buffer.from('"}\n')]));
    const bad = await agent.next();
    assert.equal(bad.uai_error?.code, "malformed"); assert.match(bad.uai_error.reason, /UTF-8/);
    agent.raw(Buffer.alloc((1 << 20) + 10, 0x61));        // no newline, over the limit
    const big = await agent.next();
    assert.equal(big.uai_error?.code, "malformed");
    agent.raw(Buffer.from("tail\n"));                      // the rest of that line is dropped, then the agent works
    agent.send({ not: "an envelope" });
    assert.equal((await agent.next()).uai_error?.code, "malformed");
  } finally { agent.stop(); }
});
