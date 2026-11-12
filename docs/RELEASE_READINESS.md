# Release readiness checklist

Nothing here has been released or tagged. This is the list to approve before a first release. Each line says what
is true today and what a release would need.

## Version

- Proposed first version: **0.1.0**. `pyproject.toml` says `0.1.0.dev0` until a release is approved.
- Reason for 0.x: no team outside this project has implemented UAI-1 yet, and no live provider run is recorded for
  this repository. 1.0.0 should wait for both.
- The wire format has its own version (`uai/1`) and does not change with the package version.

## Changelog for 0.1.0 (draft)

Added
- `uai.connect` and `uai.from_env`: one way in, seven provider routes.
- `cns_interop.providers`: Groq and Cloudflare Workers AI clients beside Anthropic, Gemini, OpenAI and Copilot.
- The `provider-call` evidence kind: a pass can carry the decider's signed record of the provider call.
- `docs/QUICKSTART.md` and `interop/examples/uai_quickstart.py`.
- UAI-1 (specification, Python and Node implementations, conformance suite), moved from CNS unchanged.

Changed
- The request digest in a provenance record is the digest of the bytes sent.
- A provider address must be https, or http to a loopback address.
- A provider call has an overall time limit, not only a limit per read.

Retired
- `uai2_gemini`, `uai2_groq`, `uai2_cloudflare` (they followed redirects). `uai2_factory` and `uai2_bridge` forward.

## Before tagging

- [ ] CI is green on this repository's default branch for Python 3.10 to 3.13. The workflow is new on this branch
      and has not run on GitHub before the pull request.
- [ ] One live run per provider you intend to name as supported (`python interop/live_providers.py --out ...`), with
      the evidence file committed. Today: none recorded here. Anthropic was run live from CNS on 2026-11-04.
- [ ] Decide the repository name. It is `UAI-2`; the package is `uai`. Renaming the repository to `UAI` would match.
- [ ] Decide whether the import name `cns_interop` stays. It is kept so that the move from CNS changed no file.
      Renaming it is mechanical but touches every import and should be its own change.
- [ ] `version` in `pyproject.toml` set to the release version, and this changelog moved to `CHANGELOG.md`.

## Pins that would need to move

- **This repository pins CNS at `v3.0.0`.** Nothing here needs a newer CNS. No pin moves for a 0.1.0 release.
- **No repository pins this one today.** The 37 repositories found pinning CNS `v2.3.0` are unaffected: that tag
  contains no UAI-1 and no provider code, so none of them could be importing what moved.
- **CNS main still carries its own copy** of `cns_interop/`, `interop/`, the UAI-1 contract files and
  `cns_composition/providers/`. Until CNS removes them there are two copies. That removal is a separate change in
  CNS, to be made after this branch is merged, because one CNS chain and one CNS module import `cns_interop` and
  must be pointed here first. The next CNS release should not ship them.

## Known limits a release note should state

- Provider behaviour is tested against local servers that speak each wire format, not against the providers.
- The signed record of a provider call is the decider's own statement; providers do not sign answers.
- Workers AI does not report why an answer ended, so a cut-off answer from it cannot be detected.
- When a model's answer is refused, the refusal reason in the signed failure can include field names the model chose.
- Provider calls honour the machine's proxy settings.
