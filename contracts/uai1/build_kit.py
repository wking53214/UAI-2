#!/usr/bin/env python3
"""build_kit.py: bundle what an outside team needs to implement UAI-1, and nothing else. Standard library only.

    python contracts/uai1/build_kit.py --out uai1-kit.zip

The kit holds the specification, the schema, the error registry, the vectors, the conformance suite and its runner, the guide, and a
report template. It holds NO implementation source (no `cns_interop`, no Node code, no example adapter), so a team that works from it
works from the documents alone. The zip lists a SHA-256 for every file in `MANIFEST.sha256`, and building twice gives identical bytes.

This is a package for an OUTSIDE team. Building it is not evidence that one exists: nobody outside this project has used it yet.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import zipfile
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[2]
PREFIX = "uai1-kit/"
FILES: List[str] = [
    "docs/interop/UAI-1.md",
    "docs/interop/SECURITY_PROFILES.md",
    "docs/interop/implementers/README.md",
    "docs/interop/implementers/DISAGREEMENT_REPORT.md",
    "contracts/uai1/schema.json",
    "contracts/uai1/errors.json",
    "contracts/uai1/conformance-suite.json",
    "contracts/uai1/run_conformance.py",
    "contracts/uai-vectors.json",
    "contracts/digest-vectors.json",
]
# Named so the guide's references to files that are not in the kit are explained, not silently dangling.
EXCLUDED = {
    "interop/conformance/reference_adapter.py": "an implementation; the kit is for working from the documents alone",
    "interop/node/conformance_adapter.mjs": "an implementation; the kit is for working from the documents alone",
    "interop/examples/": "built on the shipped implementation",
    "cns_interop/": "the Python implementation",
    "interop/node/": "the Node implementation",
    "docs/EVIDENCE.md": "project status, which names files outside the kit; the guide itself explains the one `reference` case",
}

KIT_README = """# UAI-1 implementer kit

What this is: the documents an engineering team needs to implement UAI-1 in its own language and check the result. Start at
`docs/interop/implementers/README.md`, then `docs/interop/UAI-1.md`.

What is deliberately NOT in it: any implementation source. The guide mentions two example adapters and example programs; they are
built on the shipped Python and Node code and are left out so that working from this kit means working from the documents alone.
The guide also points to `docs/EVIDENCE.md` (the project's status page); it is left out too, and the guide explains the one `reference`
case in its own text.

Check your implementation:

    python contracts/uai1/run_conformance.py --cmd "<your adapter command>"

(The runner needs only Python 3 and the standard library.) If something disagrees, fill in
`docs/interop/implementers/DISAGREEMENT_REPORT.md` and send it back: each disagreement is a bug in yours, a bug in the reference, or a
sentence in the specification that needs fixing.

Verify the kit itself: every file's SHA-256 is in `MANIFEST.sha256` (`sha256sum -c MANIFEST.sha256` from this folder).

Honest status: no team outside the project that wrote UAI-1 has implemented it yet. This kit has not been used by one.
"""


def _entries() -> Dict[str, bytes]:
    out: Dict[str, bytes] = {"KIT_README.md": KIT_README.encode("utf-8")}
    for rel in FILES:
        out[rel] = (ROOT / rel).read_bytes()
    lines = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(out.items()))
    out["MANIFEST.sha256"] = lines.encode("utf-8")
    return out


def build() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted(_entries().items()):
            info = zipfile.ZipInfo(PREFIX + name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, data)
    return buf.getvalue()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="uai1-kit.zip")
    opts = ap.parse_args()
    data = build()
    Path(opts.out).write_bytes(data)
    print(f"wrote {opts.out}: {len(_entries())} files, zip SHA-256 {hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
