// quickstart.mjs: the same exchange in Node, with the Node receiver authorizing the action. Supported public API only.
//   node interop/examples/quickstart.mjs
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import * as U from "../node/uai.mjs";
import * as G from "../node/grants.mjs";

const requester = U.signerFromSeed(randomBytes(32)), decider = U.signerFromSeed(randomBytes(32));
const cap = { name: "income-screen", version: 1, requires: ["monthly_income_cents"], accepts: ["doc_type", "monthly_income_cents"], evidence: ["threshold-check"], max_ttl_ms: 300000 };

const doc = U.commit("loan-app-17", { monthly_income_cents: 512000, doc_type: "paystub", ssn: "000-00-0000" });
const body = U.requestBody(cap.name, 1, { identity: doc.identity, digest: doc.digest, offerFields: ["monthly_income_cents", "doc_type"], requireEvidence: ["threshold-check"], maxTtlMs: 600000 });
const terms = U.proposeTerms(cap, body, { decider: decider.agent, requester: requester.agent });
const accept = U.seal(requester, "accept", { terms_digest: U.termsDigest(terms), disclosure: doc.reveal(terms.disclose) }, { to: decider.agent, ttlMs: 60000 });
const decision = U.issueDecision(decider, accept, terms, "pass", { evidence: { "threshold-check": { observed_cents: 512000 } } });
console.log("disclosed fields:", terms.disclose, "(the ssn never left)");

// The receiver. Its grant, not the signature, permits the action. Durable files stand in for a real deployment's.
const dir = mkdtempSync(join(tmpdir(), "uai-quickstart-"));
const grants = new G.GrantTable([new G.Grant({ id: "g1", capability: cap.name, version: 1, requester: requester.agent, deciders: [decider.agent], actions: ["release-funds"], disclose_max: ["doc_type", "monthly_income_cents"] })], {
  auditPath: join(dir, "audit.jsonl"), store: new G.GrantStore(join(dir, "grants.db")), permitLedger: new G.SqliteLedger(join(dir, "permits.db")) });
const guard = new U.RemoteDecisionGuard((a) => a, { actingFor: requester.agent, capability: [cap.name, 1], trust: new U.PinnedTrust([decider.agent]),
  ledger: new G.SqliteLedger(join(dir, "decisions.db")), grants, action: "release-funds" });
guard.authorize(decision, { terms, acceptDigest: U.envelopeDigest(accept) });
console.log("acting on the judged document:", guard.call([terms.subject.identity, terms.subject.digest]));
guard.complete();
console.log("permit:", guard.permit.grant, guard.permit.action, "audit chain head", G.verifyAudit(join(dir, "audit.jsonl")).slice(0, 12) + "...");
