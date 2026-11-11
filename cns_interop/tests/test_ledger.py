"""FileLedger keeps every spent message when a write fails, and loses none when it compacts.

A ledger that forgets an entry accepts a spent decision a second time, so the property under test is narrow and
absolute: after a failed `spend`, every earlier live entry still refuses as "replayed".

The failure is injected the way a real one arrives. RLIMIT_FSIZE makes the kernel return EFBIG partway through a
write, which is what a full disk or a file-size cap does, and it does not care how the ledger writes.
"""

from __future__ import annotations

import os
import resource
import signal
import threading
from contextlib import contextmanager
from typing import Iterator, List

import pytest

from cns_interop.envelope import Refused, now_ms
from cns_interop.ledger import FileLedger, MemoryLedger

SENDER = "agent:test-sender"


@contextmanager
def file_size_cap(limit: int) -> Iterator[None]:
    """Writes that would grow any file past `limit` bytes fail with EFBIG instead of raising SIGXFSZ."""
    old_handler = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, hard))
    try:
        yield
    finally:
        resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))
        signal.signal(signal.SIGXFSZ, old_handler)


def replays(ledger: FileLedger, ids: List[str]) -> List[str]:
    """The ids the ledger no longer refuses. Spending one that is still remembered raises Refused('replayed')."""
    forgotten = []
    for message_id in ids:
        try:
            ledger.spend(SENDER, message_id, now_ms() + 60_000)
        except Refused as exc:
            assert exc.code == "replayed"
        else:
            forgotten.append(message_id)
    return forgotten


@pytest.mark.parametrize("compacting", [False, True], ids=["append", "compact"])
def test_a_failed_write_forgets_nothing(tmp_path, compacting):
    path = tmp_path / "spent.jsonl"
    ledger = FileLedger(path)
    live = [f"live-{i}" for i in range(4)]
    if compacting:
        # An entry long past its keep window: the next spend drops it, so the file is rewritten, not appended to.
        ledger.spend(SENDER, "long-gone", now_ms() - 1_000_000)
    for message_id in live:
        ledger.spend(SENDER, message_id, now_ms() + 60_000)
    lines = path.read_bytes().splitlines(keepends=True)
    # The cap falls on a line boundary, so a ledger that truncates and rewrites keeps the first lines and silently
    # loses the rest; one that appends or replaces atomically keeps them all.
    cap = sum(len(line) for line in lines[:-1])

    with file_size_cap(cap), pytest.raises(OSError):
        ledger.spend(SENDER, "the-one-that-fails", now_ms() + 60_000)

    assert replays(FileLedger(path), live) == []


def test_a_failed_spend_is_not_remembered_as_spent(tmp_path):
    path = tmp_path / "spent.jsonl"
    ledger = FileLedger(path)
    ledger.spend(SENDER, "first", now_ms() + 60_000)
    size = path.stat().st_size
    with file_size_cap(size + 5), pytest.raises(OSError):  # room for a torn fragment of the next line, not the line
        ledger.spend(SENDER, "second", now_ms() + 60_000)
    assert path.read_bytes().endswith(b"\n")  # no torn line left behind to break the next read
    ledger.spend(SENDER, "second", now_ms() + 60_000)  # it never counted as spent, so it can be spent now
    assert replays(FileLedger(path), ["first", "second"]) == []


def test_compaction_leaves_no_temp_file_and_drops_only_the_expired(tmp_path):
    path = tmp_path / "spent.jsonl"
    ledger = FileLedger(path)
    ledger.spend(SENDER, "long-gone", now_ms() - 1_000_000)
    ledger.spend(SENDER, "kept", now_ms() + 60_000)  # compacts: long-gone is dropped
    assert sorted(p.name for p in tmp_path.iterdir()) == ["spent.jsonl"]
    assert replays(ledger, ["kept"]) == []
    assert replays(ledger, ["long-gone"]) == ["long-gone"]  # expired entries are meant to age out


def test_many_writers_compacting_at_once_spend_each_message_exactly_once(tmp_path):
    """Compaction replaces the file, so a writer waiting on the old file's lock must not append to the old one."""
    path = tmp_path / "spent.jsonl"
    FileLedger(path).spend(SENDER, "seed", now_ms() + 60_000)
    accepted: List[str] = []
    refused: List[str] = []
    guard = threading.Lock()

    def worker(n: int) -> None:
        ledger = FileLedger(path)
        for i in range(6):
            message_id = f"m-{i}"
            try:
                # An entry already past its keep window on every call makes each spend a compaction.
                ledger.spend(SENDER, f"stale-{n}-{i}", now_ms() - 1_000_000)
                ledger.spend(SENDER, message_id, now_ms() + 60_000)
                with guard:
                    accepted.append(message_id)
            except Refused as exc:
                assert exc.code == "replayed"
                with guard:
                    refused.append(message_id)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(accepted) == sorted({f"m-{i}" for i in range(6)})  # each message accepted by exactly one writer
    assert len(refused) == 6 * 6 - 6
    assert replays(FileLedger(path), [f"m-{i}" for i in range(6)] + ["seed"]) == []
    assert os.listdir(tmp_path) == ["spent.jsonl"]


def test_a_torn_final_line_is_cut_off_and_nothing_acknowledged_is_lost(tmp_path):
    """A process killed mid-append leaves a fragment that was never acknowledged. It must not wedge the ledger."""
    path = tmp_path / "spent.jsonl"
    ledger = FileLedger(path)
    ledger.spend(SENDER, "kept", now_ms() + 60_000)
    with open(path, "ab") as fh:
        fh.write(b'{"sender": "agent:test-sender", "id": "frag", "expi')
    ledger.spend(SENDER, "after", now_ms() + 60_000)  # was JSONDecodeError before the fix
    assert replays(ledger, ["kept", "after"]) == []
    assert path.read_bytes().endswith(b"\n")


@pytest.mark.parametrize("damage", [b"not json\n", b'{"sender": "a"}\n', b"[1]\n", b"\xff\xfe\n"],
                         ids=["garbage", "wrong-keys", "wrong-type", "bad-utf8"])
def test_damage_before_the_last_line_refuses_and_spends_nothing(tmp_path, damage):
    path = tmp_path / "spent.jsonl"
    ledger = FileLedger(path)
    ledger.spend(SENDER, "kept", now_ms() + 60_000)
    good = path.read_bytes()
    path.write_bytes(damage + good)
    with pytest.raises(Refused) as exc:
        ledger.spend(SENDER, "new", now_ms() + 60_000)
    assert exc.value.code == "unavailable"
    assert path.read_bytes() == damage + good  # nothing was written, truncated or compacted


def test_a_complete_last_line_without_a_newline_is_still_refused_as_torn_not_trusted(tmp_path):
    """A parseable fragment is cut too: only a line with its newline was ever acknowledged."""
    path = tmp_path / "spent.jsonl"
    ledger = FileLedger(path)
    path.write_bytes(b'{"sender": "agent:test-sender", "id": "unacked", "expires_at": null}')
    ledger.spend(SENDER, "unacked", now_ms() + 60_000)  # it was never acknowledged, so it is new


@pytest.mark.parametrize("kind", ["memory", "file"])
def test_a_verifier_clock_behind_the_ledgers_never_finds_a_valid_message_forgotten(tmp_path, kind):
    """The verifier still accepts a message its host clock calls long expired. The ledger must still remember it."""
    ledger = MemoryLedger() if kind == "memory" else FileLedger(tmp_path / "spent.jsonl")
    wall = now_ms()
    behind = wall - 500_000                  # the verifier's clock
    still_valid = wall - 300_000             # valid at `behind`, expired at `wall` by more than the keep window
    ledger.spend(SENDER, "victim", still_valid, now=behind)
    ledger.spend(SENDER, "other", wall + 60_000, now=behind)   # this spend would have pruned the victim
    with pytest.raises(Refused) as exc:
        ledger.spend(SENDER, "victim", still_valid, now=behind)
    assert exc.value.code == "replayed"


@pytest.mark.parametrize("kind", ["memory", "file"])
def test_a_verifier_clock_ahead_of_the_ledgers_does_not_prune_early(tmp_path, kind):
    ledger = MemoryLedger() if kind == "memory" else FileLedger(tmp_path / "spent.jsonl")
    wall = now_ms()
    ledger.spend(SENDER, "victim", wall + 30_000, now=wall + 1_000_000)
    ledger.spend(SENDER, "other", wall + 60_000, now=wall + 1_000_000)
    with pytest.raises(Refused):
        ledger.spend(SENDER, "victim", wall + 30_000, now=wall + 1_000_000)
