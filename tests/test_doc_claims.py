"""Prose that states a number the code decides is held to the code. Today: how many provider routes `uai.connect` offers."""

from __future__ import annotations

import re
from pathlib import Path

import uai

ROOT = Path(__file__).resolve().parents[1]
WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10}


def test_the_route_count_the_docs_state_for_connect_is_the_number_of_distinct_routes():
    distinct = len({id(spec) for spec in uai.PROVIDERS.values()})   # `copilot` is a second name for the Azure OpenAI route
    assert distinct == 6
    stated = []
    for rel in ("README.md", "CHANGELOG.md"):
        for line in (ROOT / rel).read_text(encoding="utf-8").splitlines():
            if "uai.connect" in line:
                for w in re.findall(r"\b(\w+) provider routes\b", line):
                    stated.append((rel, w))
    assert stated, "no doc states how many routes uai.connect offers"
    for rel, w in stated:
        assert WORDS.get(w, w) == distinct or str(w) == str(distinct), f"{rel} says {w} provider routes, uai.connect has {distinct}"
