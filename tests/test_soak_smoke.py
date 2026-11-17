"""A short run of interop/soak.py, so the soak itself is kept working. The long run (minutes to hours) is a manual job:
`python interop/soak.py --seconds 900`. This one is long enough to include a server kill and contended commits."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "interop"))
import soak  # type: ignore[import-not-found]  # noqa: E402


def test_a_short_soak_with_a_server_kill_holds_every_invariant():
    report = soak.run(seconds=25, workers=6, ids=6, seed=3, server_kills=2, verbose=False)
    assert report["findings"] == [], report["findings"]
    assert report["ok"] is True
    assert report["effects"] > 0                                    # real work happened, not an empty pass
    assert report["effects"] == report["ledger_committed"]          # the spend and the effect are one thing
    assert report["tally"].get("reserve-replayed", 0) > 0           # the same messages really were contended


def test_a_commit_cut_off_mid_flight_leaves_every_invariant_intact():
    """The window the main soak never reached: the database backend is killed while COMMIT is in flight. The outcome of such
    a commit is unknown to the worker (ambiguous), so the run must reach it, and nothing may be duplicated, lost or half done."""
    report = soak.run(seconds=25, workers=6, ids=6, seed=5, server_kills=0, verbose=False, mid_commit=0.5)
    assert report["findings"] == [], report["findings"]
    assert report["ok"] is True
    assert report["tally"].get("mid-commit-cut", 0) > 0             # commits really were cut off in flight
    assert report["ambiguous"] > 0                                  # and the workers really did not know the outcome
    assert report["ambiguous"] == report["ambiguous_committed"] + report["ambiguous_rolled_back"]
