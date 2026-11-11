"""Locate the CNS checkout so the provider protocol is importable in tests.

The UAI-2 proof is built against the CNS typed model contract
(cns_composition.providers.protocol) but does not vendor it. CNS is a
read-only reference that lives in a separate checkout. This shim puts that
checkout on sys.path when the package is not already importable.

Resolution order:
1. UAI2_CNS_PATH, if set, must point at the root of a CNS checkout.
2. A sibling directory named CNS next to this repository.
3. The original local reference checkout used when the proof was written.

CNS files are never modified from here.
"""

import importlib.util
import os
import sys

_CNS_PACKAGE = "cns_composition"
_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))

_CANDIDATES = (
    os.environ.get("UAI2_CNS_PATH", ""),
    os.path.join(os.path.dirname(_REPO_ROOT), "CNS"),
    os.path.expanduser("~/code/watcher-cns-integration-20261102/CNS"),
)


def _ensure_cns_importable():
    if importlib.util.find_spec(_CNS_PACKAGE) is not None:
        return
    for candidate in _CANDIDATES:
        if not candidate:
            continue
        candidate = os.path.abspath(candidate)
        if os.path.isdir(os.path.join(candidate, _CNS_PACKAGE)):
            sys.path.insert(0, candidate)
            return
    raise RuntimeError(
        "CNS checkout not found; set UAI2_CNS_PATH to the root of a CNS "
        "checkout that contains the cns_composition package"
    )


_ensure_cns_importable()
