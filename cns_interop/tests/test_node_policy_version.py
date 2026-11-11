"""The shared policy version in PostgreSQL, publish and require, with the same semantics in Python and in Node, and the Node
receiver (interop/node/act.mjs) running under the shared policy backend end to end.

Shown: both languages compute the SAME policy digest for the same grants (order and Unicode included); a version published by
one language is the current one for the other; only the next version can be published and a concurrent publish of one version
has exactly one winner across languages (the loser is `conflict`); a host whose grants differ from the published policy, or
that finds none, is `stale_policy` and does not act; an unreachable database is `unavailable`, never a pass; act.mjs
--policy-backend postgres acts under the published policy, writes its permits and refusals into the ONE audit chain that act.py
verifies, honours a withdrawal written by Python, refuses a stale grants file (audited as `stale_policy`), and publishes. One
machine; separate processes stand in for hosts.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, List

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from pg_cluster import Cluster  # type: ignore[import-not-found]  # noqa: E402
from test_act_policy import grants_file  # type: ignore[import-not-found]  # noqa: E402
from test_node_policy_postgres import GRANTS, codes, node, prefix  # type: ignore[import-not-found]  # noqa: E402
from test_session import ACT_PY, DEC, REQ, act_job  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.grants import load_grants  # noqa: E402
from cns_interop.policy_postgres import PostgresAudit, PostgresGrantStore, policy_digest  # noqa: E402

ROOT = str(ACT_PY.parents[1])
ACT_MJS = Path(ROOT) / "interop" / "node" / "act.mjs"
ZERO = "0" * 64
BASE = ["--acting-for", REQ.agent, "--capability", "income-screen", "--capability-version", "1", "--trust", DEC.agent]


@pytest.fixture(scope="module")
def cluster():
    c = Cluster().start()
    c.wait_ready()
    yield c
    c.cleanup()


def pcode(fn: Any, *a: Any) -> str:
    try:
        fn(*a)
    except Refused as exc:
        return exc.code  # type: ignore[no-any-return]
    return "ok"


def two(i: int, extra: str = "") -> dict:  # type: ignore[type-arg]
    return {"id": f"g{i}{extra}", "capability": "cé" if i % 2 else "pay", "version": i + 1, "requester": REQ.agent,
            "deciders": [DEC.agent, "uai:ed25519:" + "3" * 64], "actions": ["z", "a", "\U0001F600"], "disclose_max": ["b", "a"],
            "expires_at": 5_000_000_000_000 if i else None, "approvers": ["uai:ed25519:" + "4" * 64] if i == 2 else [],
            "retain_ms": i * 1000}


def test_both_languages_compute_the_same_policy_digest_whatever_the_order_or_the_text(cluster):
    docs = [GRANTS, {"grants": [two(0), two(1), two(2)]}, {"grants": [two(2), two(0), two(1)]}, {"grants": []}]
    for d in docs:
        py = policy_digest(load_grants(json.dumps(d)))
        assert node(cluster.dsn, prefix(), [["policy_digest", d]]) == [{"ok": py}]
    assert policy_digest(load_grants(json.dumps(docs[1]))) == policy_digest(load_grants(json.dumps(docs[2])))   # order-free
    assert policy_digest(load_grants(json.dumps(docs[1]))) != policy_digest(load_grants(json.dumps({"grants": [two(0), two(1), two(2, "x")]})))


def test_a_version_published_by_one_language_is_current_and_required_by_the_other(cluster):
    pre = prefix()
    py = PostgresGrantStore(cluster.dsn, prefix=pre + "_policy")
    d1, d2 = policy_digest(load_grants(json.dumps(GRANTS))), policy_digest(load_grants(json.dumps({"grants": [two(1)]})))
    assert py.current_policy() == (0, ZERO) and node(cluster.dsn, pre, [["current"]]) == [{"ok": [0, ZERO]}]
    assert codes(node(cluster.dsn, pre, [["require", d1]])) == ["stale_policy"]            # nothing published
    assert pcode(py.require_policy, d1) == "stale_policy"
    py.publish_policy(1, d1)
    assert node(cluster.dsn, pre, [["current"], ["require", d1]]) == [{"ok": [1, d1]}, {"ok": 1}]
    assert codes(node(cluster.dsn, pre, [["require", d2]])) == ["stale_policy"]            # divergent grants
    assert node(cluster.dsn, pre, [["publish", 2, d2]]) == [{"ok": True}]
    assert py.current_policy() == (2, d2) and py.require_policy(d2) == 2 and pcode(py.require_policy, d1) == "stale_policy"


def test_only_the_next_version_can_be_published_and_bad_arguments_are_caller_errors_in_both(cluster):
    pre = prefix()
    py = PostgresGrantStore(cluster.dsn, prefix=pre + "_policy")
    d = "a" * 64
    assert codes(node(cluster.dsn, pre, [["publish", 2, d], ["publish", 1, d], ["publish", 1, d], ["publish", 2, d]])) == \
        ["conflict", "ok", "conflict", "ok"]
    assert [pcode(py.publish_policy, v, d) for v in (4, 3)] == ["conflict", "ok"]
    for bad in ((0, d), (-1, d), (1.5, d), (True, d), (5, "xyz"), (5, "A" * 64), (5, d + "\n")):
        with pytest.raises(ValueError):
            py.publish_policy(*bad)
    assert codes(node(cluster.dsn, pre, [["publish", *b] for b in ((0, d), (-1, d), (1.5, d), (True, d), (5, "xyz"), (5, "A" * 64), (5, d + "\n"))])) == \
        ["caller_error"] * 7


def test_a_concurrent_publish_of_one_version_has_exactly_one_winner_across_languages(cluster):
    pre = prefix()
    py = PostgresGrantStore(cluster.dsn, prefix=pre + "_policy")

    def go(i: int) -> str:
        d = f"{i:064x}"
        return pcode(py.publish_policy, 1, d) if i % 2 else codes(node(cluster.dsn, pre, [["publish", 1, d]]))[0]
    with ThreadPoolExecutor(8) as pool:
        got = list(pool.map(go, range(8)))
    assert got.count("ok") == 1 and set(got) == {"ok", "conflict"}, got
    assert py.current_policy()[0] == 1


def test_an_unreachable_database_is_unavailable_for_require_never_a_pass(cluster):
    dead = "host=127.0.0.1 port=1 user=postgres dbname=postgres"
    assert codes(node(dead, prefix(), [["require", "a" * 64]])) == ["unavailable"]


# ------------------------------------------------------------------------------------------------ act.mjs, end to end
def args_for(home: Path, pre: str, grants: Path, *extra: str) -> List[str]:
    return [*BASE, "--ledger-backend", "postgres", "--ledger-dsn-env", "RECEIVER_DSN", "--ledger-prefix", pre,
            "--policy-backend", "postgres", "--grants", str(grants), "--action", "release-funds", *extra]


def receiver(impl: str, dsn: str, args: List[str], job: Any, env_extra: Any = None) -> Any:
    exe = shutil.which("node")
    assert exe
    cmd = [sys.executable, str(ACT_PY), *args] if impl == "py" else [exe, str(ACT_MJS), *args]
    env = {"PYTHONPATH": ROOT, "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "RECEIVER_DSN": dsn,
           "PYTHONDONTWRITEBYTECODE": "1", **(env_extra or {})}
    done = subprocess.run(cmd, input=json.dumps(job), capture_output=True, text=True, env=env, timeout=120)
    assert done.stdout, done.stderr
    return done.returncode, json.loads(done.stdout.splitlines()[-1]), done.stderr


def entries(cluster: Any, pre: str) -> list:  # type: ignore[type-arg]
    import psycopg
    with psycopg.connect(cluster.dsn, autocommit=True) as db:
        return [json.loads(r[0]) for r in db.execute(f"SELECT entry FROM {pre}_audit_chain ORDER BY seq").fetchall()]


def test_act_mjs_acts_under_the_published_policy_and_writes_the_one_chain_python_verifies(cluster, tmp_path):
    pre = "a_" + uuid.uuid4().hex[:10]
    g = grants_file(tmp_path / "grants.json")
    assert receiver("py", cluster.dsn, args_for(tmp_path, pre, g, "--publish-policy", "1"), {})[1]["published"]["version"] == 1
    rc, out, err = receiver("node", cluster.dsn, args_for(tmp_path, pre, g), act_job())
    assert rc == 0 and out["permitted"] is True and out["permit"]["grant"] == "g1", (out, err)
    assert not list(tmp_path.glob("*.db")) and not list(tmp_path.glob("*.jsonl"))                # no host-local state
    rc, out, _ = receiver("py", cluster.dsn, args_for(tmp_path, pre, g), act_job())              # Python appends to the same chain
    assert rc == 0 and out["permitted"] is True
    chain = PostgresAudit(cluster.dsn, prefix=pre + "_audit")
    assert chain.verify() == chain.head() != ZERO
    assert [e["outcome"] for e in entries(cluster, pre)] == ["permitted", "permitted"]


def test_act_mjs_honours_a_withdrawal_written_by_python_and_python_one_written_by_node(cluster, tmp_path):
    pre = "w_" + uuid.uuid4().hex[:10]
    g = grants_file(tmp_path / "grants.json")
    receiver("node", cluster.dsn, args_for(tmp_path, pre, g, "--publish-policy", "1"), {})
    PostgresGrantStore(cluster.dsn, prefix=pre + "_policy").withdraw("g1")
    rc, out, _ = receiver("node", cluster.dsn, args_for(tmp_path, pre, g), act_job())
    assert (rc, out["refused"]["code"]) == (0, "withdrawn")
    rc, out, _ = receiver("py", cluster.dsn, args_for(tmp_path, pre, g), act_job())
    assert (rc, out["refused"]["code"]) == (0, "withdrawn")
    assert [e["outcome"] for e in entries(cluster, pre)] == ["withdrawn", "withdrawn"]
    PostgresAudit(cluster.dsn, prefix=pre + "_audit").verify()


def test_act_mjs_refuses_to_start_on_stale_or_missing_policy_and_audits_it_in_the_shared_chain(cluster, tmp_path):
    pre = "s_" + uuid.uuid4().hex[:10]
    g = grants_file(tmp_path / "grants.json")
    rc, out, _ = receiver("node", cluster.dsn, args_for(tmp_path, pre, g), act_job())            # nothing published yet
    assert (rc, out["refused"]["code"]) == (2, "stale_policy")
    receiver("py", cluster.dsn, args_for(tmp_path, pre, g, "--publish-policy", "1"), {})
    other = grants_file(tmp_path / "other.json", actions=("release-funds", "extra"))
    rc, out, err = receiver("node", cluster.dsn, args_for(tmp_path, pre, other), act_job())      # this host's grants differ
    assert (rc, out["refused"]["code"]) == (2, "stale_policy")
    line = next(ln for ln in err.splitlines() if ln.startswith('{"uai_audit"'))
    assert json.loads(line)["uai_audit"]["recorded"] == "postgres"
    assert [e["outcome"] for e in entries(cluster, pre)] == ["stale_policy", "stale_policy"]
    PostgresAudit(cluster.dsn, prefix=pre + "_audit").verify()
    rc, out, _ = receiver("node", cluster.dsn, args_for(tmp_path, pre, other, "--publish-policy", "1"), {})
    assert (rc, out["refused"]["code"]) == (2, "conflict")                                       # only the next version
    rc, out, _ = receiver("node", cluster.dsn, args_for(tmp_path, pre, other, "--publish-policy", "2"), {})
    assert rc == 0 and out["published"]["version"] == 2
    assert receiver("py", cluster.dsn, args_for(tmp_path, pre, other), act_job())[1]["permitted"] is True


def test_act_mjs_policy_backend_needs_the_postgres_ledger_and_no_local_files_and_an_outage_is_unavailable(cluster, tmp_path):
    g = grants_file(tmp_path / "grants.json")
    rc, out, _ = receiver("node", cluster.dsn, [*BASE, "--ledger", str(tmp_path / "s.db"), "--policy-backend", "postgres",
                                                "--grants", str(g), "--action", "release-funds"], act_job())
    assert (rc, out["refused"]["code"]) == (2, "config") and not (tmp_path / "s.db").exists()
    rc, out, _ = receiver("node", cluster.dsn, args_for(tmp_path, "x_" + uuid.uuid4().hex[:8], g, "--grant-store", str(tmp_path / "g.db")), act_job())
    assert (rc, out["refused"]["code"]) == (2, "config") and not (tmp_path / "g.db").exists()
    rc, out, _ = receiver("node", "host=127.0.0.1 port=1 user=postgres dbname=postgres", args_for(tmp_path, "x_" + uuid.uuid4().hex[:8], g), act_job())
    assert (rc, out["refused"]["code"]) == (2, "unavailable")


def test_publish_policy_without_the_shared_policy_backend_is_refused_as_config_in_both_languages(cluster, tmp_path):
    """R2-C-16: act.py used to ignore --publish-policy unless --policy-backend postgres was given, and went on to act (or
    exit 0 having published nothing) while the operator believed a policy was published."""
    g = grants_file(tmp_path / "grants.json")
    local = [*BASE, "--ledger-backend", "postgres", "--ledger-dsn-env", "RECEIVER_DSN", "--ledger-prefix", "x_" + uuid.uuid4().hex[:8],
             "--grants", str(g), "--grant-store", str(tmp_path / "g.db"), "--action", "release-funds", "--audit", str(tmp_path / "a.jsonl"),
             "--publish-policy", "1"]
    for impl in ("py", "node"):
        rc, out, _ = receiver(impl, cluster.dsn, local, act_job())
        assert (rc, out["refused"]["code"]) == (2, "config"), (impl, out)
