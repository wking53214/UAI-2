# UAI and CNS: the dependency and research boundary

This page states exactly what UAI takes from CNS, what it does for itself, and what has and has not been shown about
the value of the dependency. It exists so that UAI can be evaluated without auditing CNS.

Checked on 2026-11-18 against UAI-2 at commit `c6c1033` and CNS at the pinned tag `v4.0.0` (commit `eabe6c7`).
Every statement about imports was read from source. Statements marked "run" were executed on that date in one Linux
container (Python 3.13, Node 22, PostgreSQL 16), with no live provider call.

Related pages: [README.md](README.md) (introduction), [README_ENGINEERING.md](README_ENGINEERING.md) (engineering
detail), [CLAIM_EVIDENCE_CROSSWALK.md](CLAIM_EVIDENCE_CROSSWALK.md) (claims and their evidence).

## 1. Summary

- UAI's Python implementation imports two things from CNS on its main path: a function that fingerprints content
  (`subject_digest`) and a three-value verdict vocabulary (`GateOutcome`). A third import is optional: it lets a
  multi-gate CNS decision leave the process as a signed UAI-1 decision.
- CNS provides no signing, signature verification, identity, trust, replay protection, authorization, key handling,
  transport or model-provider access to UAI. All of that is UAI's own code, in this repository.
- UAI's Node implementation imports nothing from CNS. It re-implements the fingerprint rule from the published
  description and vectors, and it passes the same conformance suite.
- Whether the CNS dependency gives UAI a measurable benefit has not been tested. No comparison has been run.
- CNS is also what makes a UAI decision readable by the larger system this project belongs to. That larger system is
  outside the evaluation this repository asks for (section 9).

## 2. Names that can mislead

| Name | What a reader might assume | What is true |
|---|---|---|
| `cns_interop` (the Python package) | it is part of CNS | it is UAI-1's Python implementation. It lives only in this repository and is not shipped in the CNS package. It keeps the name because UAI-1 was first developed inside the CNS repository and was moved here unchanged ([IMPORTED_FROM_CNS.md](IMPORTED_FROM_CNS.md)) |
| "the CNS subject digest" | the digest needs CNS to compute | it is a rule (a canonical text rendering, then SHA-256). Any language can implement it; the Node code here does |
| `cns_root` (a decision field) | the receiver verifies a CNS decision | it is a text field the decider signs. A receiver checks only that it is text (section 5) |
| `$id` in `contracts/uai1/schema.json` | the schema is published by CNS | the URL is left over from before the move. The schema lives here |

## 3. What UAI imports from CNS

The complete list of CNS symbols imported anywhere in this repository:

| CNS symbol | Imported by (package code first, then scripts and tests) | Purpose |
|---|---|---|
| `cns.gate.subject_digest` | `cns_interop/envelope.py`, `decision.py`, `disclosure.py`, `negotiate.py`, `grants.py`, `policy_postgres.py`, `vectors.py`; also `interop/demo.py`, `interop/campaign.py`, `cns_interop/tests/test_session.py`, `cns_interop/tests/test_node_policy_postgres.py` | the fingerprint under every signature, terms digest, field commitment and evidence digest |
| `cns.gate.GateOutcome` | `cns_interop/adapter.py`, `decision.py`, `session.py`, `uai/judge.py`; also `interop/demo.py`, `cns_interop/tests/test_session.py` | the three verdict strings: `pass`, `retry`, `terminal_breach` |
| `cns_composition.super_gate.Decision` | `cns_interop/decision.py::from_super_gate` (imported only when called) | export a decision made by a CNS gate roster as a signed UAI-1 decision |
| `cns.gate.GatePosition`, `GateResult`; `cns_composition.super_gate.SuperGate`, `Judged` | `interop/demo.py`, `cns_interop/tests/test_session.py`, `cns_interop/tests/test_partial_decision_export.py` | build a small roster for a demonstration and for tests |
| `cns.gate._canonical` (a private name) | `interop/campaign.py` | a test instrument |

A test holds the boundary in place: `cns_interop/tests/test_uai_vectors.py::test_cns_interop_imports_only_cns_cns_composition_itself_and_the_standard_library`.

Version: `pyproject.toml` requires `cns @ git+https://github.com/wking53214/CNS.git@v4.0.0`. The tag resolved to commit
`eabe6c72d71557b6327b80b42b0afab572acce80` on 2026-11-18. CNS itself has no runtime dependency.

Where to read the CNS side (three files are enough):

- the fingerprint rule for implementers: <https://github.com/wking53214/CNS/blob/v4.0.0/contracts/DIGEST.md>
- the code: <https://github.com/wking53214/CNS/blob/v4.0.0/cns/gate.py>
- the roster: <https://github.com/wking53214/CNS/blob/v4.0.0/cns_composition/super_gate.py>

The answer key for the fingerprint, `contracts/digest-vectors.json`, is copied into this repository. The copy is
byte-identical to the file at CNS `v4.0.0` (compared on 2026-11-18).

## 4. Dependency diagram

Drawn from the import statements, not from intent.

```
                         UAI-2 repository                                  CNS v4.0.0
  +-----------------------------------------------------------+     +----------------------------+
  |  uai/            connect, protocol, bridge                 |     |                            |
  |  uai/judge.py  ---------------------- GateOutcome -------------->|  cns.gate                  |
  |                                                           |     |    subject_digest          |
  |  cns_interop/    envelope, decision, disclosure,          |     |    GateOutcome             |
  |                  negotiate, grants, policy_postgres ---------->  |                            |
  |                     (subject_digest, GateOutcome)         |     |                            |
  |                                                           |     |  cns_composition           |
  |  cns_interop/decision.py::from_super_gate  - - optional - - - -> |    super_gate.Decision     |
  |                                                           |     |                            |
  |  cns_interop/    identity, ed25519, crypto_backend,       |     +----------------------------+
  |                  trust, revocation, ledger*, transport,   |
  |                  limits, providers, wire      (no CNS)    |
  |                                                           |
  |  interop/node/   uai.mjs and receivers        (no CNS)    |
  +-----------------------------------------------------------+
```

The path from a model's answer to a signed decision (`uai.connect` then `Connection.judge`) returns a plain
`Judgment`, so it never reaches `from_super_gate`. On that path CNS contributes the fingerprint function and the
verdict strings, and nothing else.

## 5. Responsibilities

Status labels, used with one meaning each:

- **IMPLEMENTED**: the code exists and was read.
- **TESTED**: an automated test in this repository checks it, and the suite passed when run on 2026-11-18.
- **DEMONSTRATED**: shown at least once outside the test suite, with the record in `evidence/` or in a run named here.
- **INFERRED**: a conclusion drawn from the above, not shown directly.
- **NOT ESTABLISHED**: no evidence.
- **OUT OF SCOPE**: deliberately not part of the evaluation this repository asks for.

| Capability or responsibility | UAI responsibility | CNS responsibility | Evidence | Status |
|---|---|---|---|---|
| Canonical fingerprint of content | calls it for every digest; narrows the allowed values (no floats, integers within 2^53 - 1, 32 levels) in `envelope.check_profile` | defines the rule and the Python function; publishes the vectors | `contracts/digest-vectors.json`; `cns_interop/tests/test_uai_vectors.py`; both conformance adapters 72 of 72 (run) | TESTED |
| The same fingerprint without the CNS package | Node re-implements it in `interop/node/uai.mjs` | none at run time; the rule text and vectors only | Node conformance 72 of 72 (run); CNS CI job `digest-second-language` | TESTED |
| Verdict vocabulary | uses the three strings on the wire and in the strict reader | defines the enum | `cns_interop/tests/test_adapter.py`, `test_session.py` | TESTED |
| Export of a roster decision | `decision.from_super_gate` refuses a decision not issued in this process, and sends a partial pass as a breach | `SuperGate.decide` makes the decision and its root | `cns_interop/tests/test_session.py`, `test_partial_decision_export.py`, `test_two_systems.py::test_node_requests_a_cns_super_gate_decides_and_node_verifies`; `interop/demo.py` (run) | TESTED |
| Meaning of `cns_root` at the receiver | carries and signs the text | produced it | `cns_interop/decision.py` and `interop/node/uai.mjs` check only that it is text | IMPLEMENTED as an opaque field. That a receiver can verify the roster behind it: NOT ESTABLISHED |
| Signing and signature verification | all of it: `ed25519.py`, `crypto_backend.py`, `identity.py`, `envelope.py`; `uai.mjs` | none | conformance suite; `test_ed25519.py`, `test_crypto_backend.py`, `test_envelope.py` | TESTED |
| Identity and trust (pinning, endorsement, revocation, rotation) | all of it: `identity.py`, `trust.py`, `revocation.py` | none | `test_trust.py`, `test_revocation.py` | TESTED |
| Replay protection | all of it: `ledger.py`, `ledger_postgres.py`, `interop/node/pg.mjs` | none | `test_ledger.py`, `test_ledger_postgres.py`, soak reports in `evidence/` | TESTED on one machine |
| Authorization (grants, approvals, single-use permits, audit) | all of it: `grants.py`, `policy_postgres.py`, `interop/node/grants.mjs` | none | `test_grants_enforced.py`, `test_node_receiver_parity.py` | TESTED |
| Access to model providers | all of it: `cns_interop/providers.py`, `uai/` | none | `tests/test_provider_layer.py`, `tests/test_front_door.py`; live rows in `evidence/` | TESTED against local stand-in servers. Four client functions DEMONSTRATED live; `uai.connect` itself only against stand-ins |
| Typed model contract (`ModelRequest`, `ModelResponse`) | `uai/protocol.py` is the copy UAI uses | CNS ships an identical file at `cns_composition/providers/protocol.py`, which UAI does not import | files compared byte for byte on 2026-11-18 | IMPLEMENTED twice. Nothing keeps the two copies the same |
| Transport security | `cns_interop/transport.py` (TLS 1.3 mutual profile) | none | `test_transport.py` | TESTED |
| Key custody as an operating procedure | draft in [docs/KEY_CUSTODY.md](docs/KEY_CUSTODY.md) | none | simulated drill only | NOT ESTABLISHED |
| A measurable benefit from depending on CNS | | | none | NOT ESTABLISHED |
| Joining UAI to the larger system through CNS | | | section 9 | OUT OF SCOPE |

## 6. What UAI would need if CNS were absent

1. Its own copy of the fingerprint function. In CNS it is two functions in one file. The Node implementation in this
   repository already carries its own.
2. The three verdict strings as constants.
3. Either its own roster mechanism, or no `from_super_gate` export. The `cns_root` field would stay empty, which the
   specification already allows.

No security control would have to be weakened to do this, because CNS supplies none of UAI's controls. That is an
inference from the import list in section 3, not the result of building such a version in Python.

## 7. CNS capabilities UAI does not use

At `v4.0.0` the CNS package ships 49 non-test Python modules. UAI imports from two of them. Unused by UAI:

- in `cns`: every module except `gate` and `rowenum`, which `gate` imports for the base class of its enums (unused:
  assay, attack, caller, defect, epistemic, finding, governance, graph, perception, run, seat, stack, suite), and
  within `gate` the `Gate` protocol, `GateChain`,
  `resolve` and `unbound` (the roster uses them internally);
- in `cns_composition`: every module except `super_gate` and what it imports internally (`gate_chain`, `repo_gates`),
  including its own provider adapter under `cns_composition/providers/`;
- CNS's chain scripts, release tooling and evidence folders.

## 8. What the dependency costs

| Cost | Detail |
|---|---|
| Installation | CNS is not on a package index. `pip install` fetches it from GitHub, so it needs git and network access |
| A movable pin | the requirement names a tag, and a tag can be re-pointed. The commit it resolves to is recorded above but is not enforced |
| A rule defined elsewhere | the implementer-level description of the fingerprint (`contracts/DIGEST.md`) is in the CNS repository. This repository and the implementer kit carry the vectors and a shorter table in [docs/interop/UAI-1.md](docs/interop/UAI-1.md) section 1 |
| A duplicated contract | the typed model contract exists in both repositories (section 5) |
| Naming | the package name and the schema `$id` suggest CNS provides UAI-1 (section 2) |
| Coupling in continuous integration | CNS's own CI checks out this repository for two of its chain jobs, so the two repositories refer to each other there, though not as packages |
| Version drift | CNS is now at 4.1.0. The change to `cns/gate.py` between 4.0.0 and 4.1.0 adds two types and does not touch `subject_digest` (read from the diff). UAI has not been run against 4.1.0 here |

## 9. Context: the larger system (out of scope)

CNS is the shared vocabulary of a larger library of repositories by the same author (written ≡TACK, read "STACK").
Because UAI uses CNS's verdict strings and fingerprint rule, a signed UAI-1 decision is already in the form those
repositories read. That is the reason the dependency exists, and it is where any benefit of CNS to UAI would appear.

The join is exercised by scripts in the CNS repository, not here:
<https://github.com/wking53214/CNS/blob/main/chains/uai_to_ccc.py> runs a path from a model's answer, through a signed
UAI-1 decision and the receiver's own grant, into another repository's store. Run offline on 2026-11-18 with stand-in
models, at the then-current commits of seven repositories: 13 of 13 scenarios gave the outcome each requires. One
live run of the same script is recorded in
[evidence/live-runs/2026-11-13-uai-to-ccc-live/](evidence/live-runs/2026-11-13-uai-to-ccc-live/README.md).

This repository does not ask a reviewer to evaluate that system. It could be a second stage.

## 10. A comparison a researcher could run

None of this has been run. It is offered as a design.

| Condition | What it is | Already available |
|---|---|---|
| A. UAI without the CNS package | the same protocol with its own fingerprint function and verdict constants, all controls unchanged | the Node implementation is this condition. A Python version would need the small changes in section 6 |
| B. UAI with CNS | the Python implementation as shipped | yes |
| C. Comparison | measure what differs between A and B | no |

Measurements that would mean something:

- lines of code and number of dependencies in each condition;
- whether A and B produce identical digests and identical accept or refuse answers on the conformance suite and on
  mutated inputs (the existing differential fuzz, `interop/diff_fuzz.py`, already compares Python with Node);
- installation steps and failure modes for a newcomer in each condition;
- what breaks in each condition when CNS changes version;
- for the roster export only: whether a receiver gains anything checkable from `cns_root`.

What a researcher should not expect to find: a difference in signing, verification, replay or authorization behaviour.
CNS does not take part in those.

A fair reading of the result: if A and B behave identically and A is simpler to install, the dependency is a
convenience for the author's larger system and a cost for anyone using UAI alone. If keeping one shared definition
prevents the two implementations from drifting apart over time, that is a benefit, and it would show up only across
several versions.
