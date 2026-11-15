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
