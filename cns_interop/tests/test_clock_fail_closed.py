"""RACE-02 I-07b (R2-C-04, R2-C-05, R2-C-09, R2-C-12): a database time that is missing, malformed, non-finite, negative or
implausible fails closed as `unavailable` in BOTH receivers, and every refusal to start or to sync is audited.

The defects this closes, each shown first against the code of Step 3:
  * R2-C-04: the Node check treated a non-numeric answer (`NaN`) as agreement, so act.mjs ACTED against a database whose time
    it could not read.
  * R2-C-09: act.py crashed with a traceback on a NULL time, and act.mjs labelled it `config`; an implausible time (before
    2000, negative) was reported as `clock_skew`, which says the host is wrong when it is the reference that is.
  * R2-C-05: the start-up refusals (`clock_skew`, `unavailable`, `config`) left no record at all.
  * R2-C-12 (found while writing these): the PostgreSQL ledger itself, asked to spend a message while the database's clock
    answers NULL, accepted an expired message (spend) or crashed after writing a lease row (Python reserve).

Real PostgreSQL throughout. The database's SQL clock is moved by pg_testclock (NULL, a year-1900 answer, infinity, NULL from
the second reading on); a Node-only stand-in for `psql` supplies answers a real server cannot give (`NaN`, `-5`, `1e3`), and
is test code, not part of either program. Not shown: a database whose own wall clock is moved (one machine, one clock).
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Optional

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import pg_testclock  # type: ignore[import-not-found]  # noqa: E402
from pg_cluster import Cluster  # type: ignore[import-not-found]  # noqa: E402
from test_clock_trust import HOUR, ROOT  # type: ignore[import-not-found]  # noqa: E402,F401
from test_clock_trust_production import (  # type: ignore[import-not-found]  # noqa: E402
    PRODUCTION, node_local_args, no_state, prefix, publish, refused, run_receiver, shared_policy_args)
from test_session import act_job  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.grants import verify_audit  # noqa: E402
from cns_interop.ledger_postgres import PostgresLedger  # noqa: E402
from cns_interop.policy_postgres import PostgresAudit  # noqa: E402

PG_ARGS = ["--ledger-backend", "postgres", "--ledger-dsn-env", "RECEIVER_DSN"]
IMPLS = ["py", "node"]


@pytest.fixture(scope="module")
def cluster():
    c = Cluster().start()
    c.wait_ready()
    pg_testclock.install(c.dsn)
    yield c
    c.cleanup()


@pytest.fixture(autouse=True)
def real_db_clock(cluster):
    pg_testclock.set_clock(cluster.dsn)
    yield
    pg_testclock.set_clock(cluster.dsn)


def local_args(home: Path) -> list:
    return [*node_local_args(home, [*PG_ARGS, "--ledger-prefix", prefix()]), "--max-clock-skew-ms", "5000"]


def audit_line(stderr: str) -> dict:
    """The structured `{"uai_audit": {...}}` line a refusal to start writes on stderr."""
    lines = [json.loads(ln)["uai_audit"] for ln in stderr.splitlines() if ln.startswith('{"uai_audit"')]
    assert len(lines) == 1, stderr
    return lines[0]


def last_entry(path: Path) -> dict:
    return json.loads(path.read_text().splitlines()[-1])


def fake_psql(home: Path, answer: Optional[str]) -> dict:
    """A `psql` on PATH that answers the receiver's time query with `answer` (and runs the real psql for everything else).
    Test only: a real server cannot answer `NaN` to a bigint cast."""
    real = shutil.which("psql")
    assert real, "psql is not installed"
    (home / "bin").mkdir(parents=True, exist_ok=True)
    shim = home / "bin" / "psql"
    shim.write_text(f"""#!/bin/sh
if [ "$1" = "--version" ]; then exec {real} --version; fi
q=$(cat)
t="BEGIN;
SELECT (extract(epoch from clock_timestamp()) * 1000)::bigint;
COMMIT;"
if [ -f "$HOME/fake_time" ] && [ "$q" = "$t" ]; then cat "$HOME/fake_time"; exit 0; fi
printf '%s\\n' "$q" | exec {real} "$@"
""")
    shim.chmod(shim.stat().st_mode | stat.S_IEXEC)
    if answer is not None:
        (home / "fake_time").write_text(answer)
    return {"PATH": f"{home / 'bin'}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}"}


# --------------------------------------------------------------------------------------- the time the database answers

@pytest.mark.parametrize("row", [None, (), (None,), ("12",), (True,), (1.5,), (-1,), (0,), (946_684_799_999,), (2 ** 53,),
                                 (2 ** 60,), (1, 2), [None]])
def test_python_reads_a_database_time_only_when_it_is_a_plausible_integer(row):
    from cns_interop.ledger_postgres import _server_time
    with pytest.raises(Refused) as e:
        _server_time(row)
    assert e.value.code == "unavailable"


def test_python_accepts_a_plausible_time():
    from cns_interop.ledger_postgres import _server_time
    assert _server_time((1_793_000_000_000,)) == 1_793_000_000_000
    assert _server_time([946_684_800_000]) == 946_684_800_000


@pytest.mark.parametrize("impl", IMPLS)
@pytest.mark.parametrize("mode", ["null", "year1900", "infinity"])
def test_a_database_that_gives_no_usable_time_is_unavailable_and_the_refusal_is_audited(cluster, tmp_path, impl, mode):
    """R2-C-09: a NULL time crashed act.py and was `config` in act.mjs; a year-1900 time was `clock_skew`."""
    home = tmp_path / impl
    args = local_args(home)
    pg_testclock.set_clock(cluster.dsn, mode=mode)
    result = run_receiver(impl, home, args, act_job(), cluster.dsn)
    assert refused(result) == (2, "unavailable"), result
    line = audit_line(result[2])
    assert line["outcome"] == "unavailable" and line["stage"] == "startup" and line["recorded"] == "file", line
    assert no_state(home)
    entry = last_entry(home / "audit.jsonl")
    assert entry["outcome"] == "unavailable" and entry["stage"] == "startup" and entry["digest"] == verify_audit(home / "audit.jsonl")


@pytest.mark.parametrize("answer", ["NaN", "-5", "abc", "1e3", "1.5", "Infinity", "0", "42", "12345678901234567890", "1\t2"])
def test_node_refuses_a_time_it_cannot_read_instead_of_treating_it_as_agreement(cluster, tmp_path, answer):
    """R2-C-04: `NaN` used to pass the skew check (`Math.abs(NaN) > max` is false) and act.mjs went on to ACT."""
    home = tmp_path / "n"
    env = fake_psql(home, answer + "\n")
    result = run_receiver("node", home, local_args(home), act_job(), cluster.dsn, env_extra=env)
    assert refused(result) == (2, "unavailable"), result
    assert no_state(home)


def test_the_stand_in_for_psql_is_transparent_when_it_does_not_answer_the_time_query(cluster, tmp_path):
    home = tmp_path / "n"
    env = fake_psql(home, None)
    rc, out, err = run_receiver("node", home, local_args(home), act_job(), cluster.dsn, env_extra=env)
    assert rc == 0 and out["permitted"] is True, (out, err)


# --------------------------------------------------------------------------------------------------------- the ledger

def rows(cluster, table: str) -> int:
    import psycopg
    with psycopg.connect(cluster.dsn) as db:
        return int(db.execute(f"SELECT count(*) FROM {table}").fetchone()[0])  # type: ignore[index]


@pytest.mark.parametrize("mode", ["null", "year1900"])
def test_python_ledger_fails_closed_when_the_database_clock_answers_nothing(cluster, mode):
    """R2-C-12: spend accepted an expired message (NULL >= x is not true) and reserve wrote a lease row, then crashed."""
    table = "t_" + uuid.uuid4().hex[:12]
    led = PostgresLedger(cluster.dsn, table=table)
    real = pg_testclock.real_now_ms(cluster.dsn)
    pg_testclock.set_clock(cluster.dsn, mode=mode)
    for expires_at in (real - 10_000_000, real + 60_000, None):
        with pytest.raises(Refused) as e:
            led.spend("uai:ed25519:" + "a" * 64, uuid.uuid4().hex, expires_at)
        assert e.value.code == "unavailable"
        with pytest.raises(Refused) as e:
            led.reserve("uai:ed25519:" + "a" * 64, uuid.uuid4().hex, expires_at, lease_ms=1000)
        assert e.value.code == "unavailable"
    assert rows(cluster, table) == 0


@pytest.mark.parametrize("mode", ["null", "year1900"])
def test_node_ledger_fails_closed_when_the_database_clock_answers_nothing(cluster, mode):
    table = "t_" + uuid.uuid4().hex[:12]
    PostgresLedger(cluster.dsn, table=table)
    real = pg_testclock.real_now_ms(cluster.dsn)
    pg_testclock.set_clock(cluster.dsn, mode=mode)
    js = f"""import {{ PostgresLedger }} from {json.dumps((Path(ROOT) / "interop" / "node" / "pg.mjs").as_uri())};
const l = new PostgresLedger(process.env.RECEIVER_DSN, {{ table: {json.dumps(table)} }}), out = [];
for (const exp of [{real - 10_000_000}, {real + 60_000}, null]) {{
  for (const op of ["spend", "reserve"]) {{
    try {{ if (op === "spend") l.spend("s", crypto.randomUUID(), exp); else l.reserve("s", crypto.randomUUID(), exp, {{ leaseMs: 1000 }}); out.push("ACCEPTED"); }}
    catch (e) {{ out.push(e.code ?? e.name); }}
  }}
}}
console.log(JSON.stringify(out));"""
    done = subprocess.run([shutil.which("node") or "node", "--input-type=module", "-e", js], capture_output=True, text=True,
                          env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "RECEIVER_DSN": cluster.dsn}, timeout=120)
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == ["unavailable"] * 6
    assert rows(cluster, table) == 0


# -------------------------------------------------------------------------------------------------------- the audit

@pytest.mark.parametrize("impl", IMPLS)
def test_a_clock_skew_refusal_is_appended_to_the_hash_chained_audit_file_in_either_language(cluster, tmp_path, impl):
    home = tmp_path / impl
    result = run_receiver(impl, home, local_args(home), act_job(), cluster.dsn, shift_ms=-HOUR)
    assert refused(result) == (2, "clock_skew")
    line = audit_line(result[2])
    assert line["recorded"] == "file" and line["audit_error"] == "" and line["outcome"] == "clock_skew"
    entry = last_entry(home / "audit.jsonl")
    assert (entry["outcome"], entry["stage"], entry["profile"]) == ("clock_skew", "startup", "default")
    assert "differs from the ledger database's" in entry["reason"]
    assert entry["digest"] == verify_audit(home / "audit.jsonl")      # the chain verifies, whichever language wrote the entry
    # the next refusal chains onto the first: one chain, two entries
    run_receiver(impl, home, local_args(home), act_job(), cluster.dsn, shift_ms=-HOUR)
    assert len((home / "audit.jsonl").read_text().splitlines()) == 2 and verify_audit(home / "audit.jsonl")


def test_the_chain_is_shared_by_python_and_node_refusals(cluster, tmp_path):
    home = tmp_path / "both"
    for impl in ("py", "node", "py"):
        assert refused(run_receiver(impl, home, local_args(home), act_job(), cluster.dsn, shift_ms=-HOUR)) == (2, "clock_skew")
    assert len((home / "audit.jsonl").read_text().splitlines()) == 3 and verify_audit(home / "audit.jsonl")


@pytest.mark.parametrize("impl", IMPLS)
def test_a_config_refusal_is_audited_too(cluster, tmp_path, impl):
    home = tmp_path / impl
    args = [*local_args(home)[:-2], "--max-clock-skew-ms", "120000"]       # not below keep_ms
    result = run_receiver(impl, home, args, act_job(), cluster.dsn)
    assert refused(result) == (2, "config") and "keep" in result[1]["refused"]["reason"].lower()
    assert last_entry(home / "audit.jsonl")["outcome"] == "config" and audit_line(result[2])["recorded"] == "file"
    assert no_state(home)


@pytest.mark.parametrize("impl", IMPLS)
def test_a_refusal_that_cannot_be_recorded_still_leaves_its_line_and_says_why(cluster, tmp_path, impl):
    """Never swallowed: the audit path is a directory, so the record fails; the refusal and the line are unchanged."""
    home = tmp_path / impl
    args = local_args(home)
    args[args.index("--audit") + 1] = str(home)                            # a directory is not an audit file
    result = run_receiver(impl, home, args, act_job(), cluster.dsn, shift_ms=-HOUR)
    assert refused(result) == (2, "clock_skew")
    line = audit_line(result[2])
    assert line["recorded"] is None and line["audit_error"] and line["outcome"] == "clock_skew", line


@pytest.mark.parametrize("impl", IMPLS)
def test_with_no_audit_sink_a_refusal_is_still_one_structured_line(cluster, tmp_path, impl):
    """A decision-only receiver has no audit record (that is its stated limit); the refusal is the line, and says so."""
    home = tmp_path / impl
    pg = [*PG_ARGS, "--ledger-prefix", prefix(), "--decision-only", "--max-clock-skew-ms", "5000"]
    from test_clock_trust_production import BASE  # type: ignore[import-not-found]
    result = run_receiver(impl, home, [*BASE, *pg], act_job(), cluster.dsn, shift_ms=-HOUR)
    assert refused(result) == (2, "clock_skew")
    line = audit_line(result[2])
    assert line["recorded"] is None and line["audit_error"] == "" and line["stage"] == "startup"


def test_python_production_refusals_are_appended_to_the_shared_postgres_chain(cluster, tmp_path):
    pre = prefix()
    publish(cluster, tmp_path, pre)
    chain = PostgresAudit(cluster.dsn, prefix=pre + "_audit")
    before = chain.verify()
    skewed = run_receiver("py", tmp_path, [*shared_policy_args(tmp_path, pre), "--max-clock-skew-ms", "5000"], act_job(),
                          cluster.dsn, env_extra=PRODUCTION, shift_ms=-HOUR)
    assert refused(skewed) == (2, "clock_skew") and audit_line(skewed[2])["recorded"] == "postgres"
    no_flag = run_receiver("py", tmp_path, shared_policy_args(tmp_path, pre), act_job(), cluster.dsn, env_extra=PRODUCTION)
    assert refused(no_flag) == (2, "config") and audit_line(no_flag[2])["recorded"] == "postgres"
    import psycopg
    with psycopg.connect(cluster.dsn) as db:
        entries = [json.loads(r[0]) for r in db.execute(f"SELECT entry FROM {pre}_audit_chain ORDER BY seq").fetchall()]
    assert [e["outcome"] for e in entries[-2:]] == ["clock_skew", "config"] and entries[-1]["profile"] == "production"
    assert chain.verify() != before                                         # the chain advanced, and still verifies end to end


# ---------------------------------------------------------------------------------- the database goes bad after start-up

@pytest.mark.parametrize("impl", IMPLS)
def test_a_database_that_goes_bad_between_startup_and_the_decision_refuses_the_decision_audited_and_does_not_spend_it(cluster, tmp_path, impl):
    """The clock is read at start-up (reading 1) and again for the decision (reading 2). From the second on the database
    answers NULL: the decision is refused `unavailable`, recorded as stage `decision`, and not consumed."""
    home = tmp_path / impl
    args = local_args(home)
    job = act_job()
    pg_testclock.set_clock(cluster.dsn, null_from_call=2)
    rc, out, err = run_receiver(impl, home, args, job, cluster.dsn)
    assert (rc, out["refused"]["code"]) == (0, "unavailable"), (out, err)       # a refused decision is an answer (exit 0), as ever
    line = audit_line(err)
    assert line["stage"] == "decision" and line["recorded"] == "file" and line["outcome"] == "unavailable", line
    assert last_entry(home / "audit.jsonl")["stage"] == "decision" and verify_audit(home / "audit.jsonl")
    pg_testclock.set_clock(cluster.dsn)
    rc, out, err = run_receiver(impl, home, args, job, cluster.dsn)
    assert rc == 0 and out["permitted"] is True, (out, err)                      # the same decision: it was never spent
