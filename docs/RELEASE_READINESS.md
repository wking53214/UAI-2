# Release readiness checklist

Nothing here has been released or tagged. This is the list to approve before a first release. Each line says what
is true today and what a release would need.

## Version

- Proposed first version: **0.1.0**. `pyproject.toml` says `0.1.0` as of the release PR; no tag has been cut.
- Reason for 0.x: no team outside this project has implemented UAI-1 yet, and two of the seven provider routes
  (OpenAI, Azure OpenAI) have not been run live; a third, GitHub Models, was retired by GitHub on 2026-07-30 and no longer
  works. 1.0.0 should wait for both gaps, and for a decision on that dead route.
- The wire format has its own version (`uai/1`) and does not change with the package version.

## Changelog for 0.1.0

Moved to `CHANGELOG.md`.

## Before tagging

- [x] CI is green on this repository's default branch for Python 3.10 to 3.13: run #36 on `60e103a` (the PR #8
      merge), 2026-11-12. It runs on every push. From the PR #4 merge to the PR #7 merge it failed at the type-check
      step only (tests, conformance and lint passed on all four versions); PR #8 fixed it. Keep it green: a red main
      reopens this item.
- [ ] One live run per provider you intend to name as supported (`python interop/live_providers.py --out ...`), with
      the evidence file committed. Today: Anthropic, Gemini, Groq and Cloudflare Workers AI answered live on 2026-11-12
      (recorded in `docs/EVIDENCE.md` and `evidence/live-runs/`, from the printed output; the JSON evidence files
      themselves were not committed). OpenAI and Azure OpenAI: not run. GitHub Models: retired by GitHub on 2026-07-30.
- [x] Repository name: decided 2026-11-12 by the project owner to keep `UAI-2` for now. The package is `uai`; renaming the
      repository to `UAI` would match and can be done later, since it needs only a GitHub rename and link updates.
- [x] Import name: decided 2026-11-12 by the project owner to keep `cns_interop` for now. It is kept so that the move from
      CNS changed no file. Renaming it is mechanical but touches every import and test and should be its own change, after
      it is known who imports it.
- [x] `version` in `pyproject.toml` set to 0.1.0, and the changelog moved to `CHANGELOG.md` (release PR; no tag yet).

## Pins that would need to move

- **This repository pins CNS at `v4.0.0`.** Nothing here needs a newer CNS. No pin moves for a 0.1.0 release.
- **No repository pins this one today.** The 37 repositories found pinning CNS `v2.3.0` are unaffected: that tag
  contains no UAI-1 and no provider code, so none of them could be importing what moved.
- **CNS no longer carries its own copy** of `cns_interop/` and `interop/`: CNS PR #126 removed it, and CNS v3.0.0
  checks this repository out where it needs them (its evidence chain). There is one copy, here.

## Known limits a release note should state

- Provider behaviour is tested against local servers that speak each wire format. Four routes have also answered
  live (see `docs/EVIDENCE.md`); a live run is a snapshot, not a test CI repeats.
- The signed record of a provider call is the decider's own statement; providers do not sign answers.
- Older Workers AI catalog models do not report why an answer ended, so a cut-off answer from them cannot be
  detected. Newer models answer in the Chat Completions shape, which does report it, and the client reads that.
- When a model's answer is refused, the refusal reason in the signed failure can include field names the model chose.
- Provider calls honour the machine's proxy settings.
