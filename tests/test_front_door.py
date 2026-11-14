"""uai.connect and what it hands back: selection, the typed bridge over every provider, and the path from a model's
recommendation to a signed UAI-1 decision that the Node implementation verifies. EVERY SERVER HERE IS A STUB.

This file replaces tests/test_uai2_factory.py, test_uai2_factory_failures.py, test_uai2_gemini.py, test_uai2_groq.py
and test_uai2_cloudflare.py, which tested the three adapter classes this branch retires. What those tests held (the
selection rules, the common response shape, failure categories that match across providers, a key that appears in no
result or error) is held here against the one provider layer, for all seven routes instead of three.
"""

from __future__ import annotations

import importlib
import json
import secrets
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cns_interop" / "tests"))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "interop"))
from test_adapter import honest_model, policy  # type: ignore[import-not-found]  # noqa: E402
from test_provider_layer import (ALL, FAILURES, KEY, LABEL, answering, cut_off, plain,  # type: ignore[import-not-found]  # noqa: E402
                                 serving)
from test_session import DEC, REQ, doc  # type: ignore[import-not-found]  # noqa: E402

import uai  # noqa: E402
import uai2_factory  # noqa: E402
from cns_interop.adapter import ProviderInfo  # noqa: E402
from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.identity import Signer  # noqa: E402
from cns_interop.manifest import Capability  # noqa: E402
from cns_interop.providers import ProvenanceLog  # noqa: E402
from cns_interop.session import Decider, Requester  # noqa: E402
from cns_interop.trust import TrustPolicy  # noqa: E402
from uai.protocol import CompletionStatus, ModelProvider, ModelRequest, ModelResponse, TokenUsage  # noqa: E402

NAME = {"anthropic": "anthropic", "gemini": "gemini", "openai": "openai", "copilot": "copilot", "copilot-azure": "copilot-azure",
        "groq": "groq", "cloudflare": "cloudflare"}
KEY_VAR = {"anthropic": "ANTHROPIC_API_KEY", "gemini": "GEMINI_API_KEY", "openai": "OPENAI_API_KEY",
           "copilot": "AZURE_OPENAI_API_KEY", "copilot-azure": "AZURE_OPENAI_API_KEY", "groq": "GROQ_API_KEY",
           "cloudflare": "CLOUDFLARE_API_TOKEN"}
MODEL = {p: "model-x" for p in ALL} | {"cloudflare": "@cf/meta/model-x"}
# GitHub Models is retired (2026-07-30): the front door's `copilot` now means the Azure OpenAI route, so through `uai.connect`
# it is recorded under the Azure label. The lower-level client's own default route is untouched and still tested elsewhere.
LABEL = {**LABEL, "copilot": "copilot-azure-openai"}


def env_for(provider, **more):
    env = {KEY_VAR[provider]: KEY, **more}
    if provider == "cloudflare":
        env.setdefault("CLOUDFLARE_ACCOUNT_ID", "acct123")
    return env


def connected(provider, url, **kw):
    return uai.connect(NAME[provider], MODEL[provider], environ=env_for(provider), base_url=url, **kw)


def request(provider, **kw):
    fields = dict(model=MODEL[provider], system_instruction="", user_messages=("portable prompt",), max_output_tokens=512,
                  generation_settings={})
    return ModelRequest(**{**fields, **kw})


# ---------------------------------------------------------------------------------------------------- selection
def test_the_provider_is_always_named_and_a_stray_key_selects_nothing():
    everything = {v: KEY for v in KEY_VAR.values()} | {"CLOUDFLARE_ACCOUNT_ID": "acct123", "AZURE_OPENAI_ENDPOINT": "https://x.example"}
    with pytest.raises(ValueError, match="UAI_PROVIDER is not set"):
        uai.from_env(everything)                       # every key present, and still nothing is chosen for the caller
    with pytest.raises(ValueError, match="UAI_MODEL is not set"):
        uai.from_env({**everything, "UAI_PROVIDER": "groq"})
    got = uai.from_env({**everything, "UAI_PROVIDER": "groq", "UAI_MODEL": "m"})
    assert (got.name, got.provider, got.model) == ("groq", "groq", "m")


@pytest.mark.parametrize("provider", ALL)
def test_each_provider_is_reached_by_its_name_and_reads_its_own_key_variable(provider):
    more = {"AZURE_OPENAI_ENDPOINT": "https://res.example"} if provider in ("copilot", "copilot-azure") else {}
    got = uai.connect(NAME[provider].upper() + "  ", " " + MODEL[provider] + " ", environ=env_for(provider, **more))
    assert got.provider == LABEL[provider] and got.model == MODEL[provider] and callable(got.complete)
    with pytest.raises(ValueError) as e:
        uai.connect(NAME[provider], MODEL[provider], environ={k: v for k, v in env_for(provider, **more).items() if k != KEY_VAR[provider]})
    assert KEY_VAR[provider] in str(e.value) and KEY not in str(e.value)


def test_the_anthropic_key_is_read_from_the_uai_variable_first():
    stub = serving("anthropic", plain)
    try:
        both = {"UAI_ANTHROPIC_API_KEY": "sk-first-0123456789", "ANTHROPIC_API_KEY": "sk-second-0123456789"}
        uai.connect("anthropic", "m", environ=both, base_url=stub.url).complete("hi")
        assert stub.requests[0]["headers"]["x-api-key"] == "sk-first-0123456789"
    finally:
        stub.close()


@pytest.mark.parametrize("bad", ["", "  ", "bard", "gemini,groq", "../groq", None, 7])
def test_an_unknown_provider_is_refused_with_the_list_of_known_ones(bad):
    with pytest.raises(ValueError, match="expected one of: anthropic, cloudflare, copilot, copilot-azure, gemini, groq, openai"):
        uai.connect(bad, "m", environ={})


@pytest.mark.parametrize("model", ["", "   ", None])
def test_a_missing_model_is_refused(model):
    with pytest.raises(ValueError, match="model"):
        uai.connect("groq", model, environ=env_for("groq"))


def test_what_else_a_provider_needs_is_named_when_it_is_missing():
    with pytest.raises(ValueError, match="CLOUDFLARE_ACCOUNT_ID"):
        uai.connect("cloudflare", "m", environ={"CLOUDFLARE_API_TOKEN": KEY})
    with pytest.raises(ValueError, match="CLOUDFLARE_API_TOKEN"):
        uai.connect("cloudflare", "m", environ={"CLOUDFLARE_ACCOUNT_ID": "acct123"})
    with pytest.raises(ValueError, match="AZURE_OPENAI_ENDPOINT"):
        uai.connect("copilot-azure", "m", environ={"AZURE_OPENAI_API_KEY": KEY})


@pytest.mark.parametrize("key", ["sk-SECRET\ninjected: header", "sk-SECRET tail", "sk-​SECRET", "sk-SECRET\ttail"])
def test_a_key_with_whitespace_or_a_hidden_character_inside_is_refused_and_never_shown(key):
    with pytest.raises(ValueError) as e:
        uai.connect("groq", "m", environ={"GROQ_API_KEY": key})
    assert "SECRET" not in str(e.value)


def test_a_newline_at_the_end_of_a_pasted_key_is_dropped_not_sent():
    stub = serving("groq", plain)
    try:
        uai.connect("groq", "m", environ={"GROQ_API_KEY": KEY + "\n"}, base_url=stub.url).complete("hi")
        assert stub.requests[0]["headers"]["authorization"] == "Bearer " + KEY
    finally:
        stub.close()


def test_the_old_and_new_setting_names_are_one_setting_and_may_not_disagree():
    base = env_for("groq")
    assert uai.from_env({**base, "UAI2_PROVIDER": "groq", "UAI2_MODEL": "m"}).name == "groq"
    assert uai.from_env({**base, "UAI_PROVIDER": "groq", "UAI2_PROVIDER": "groq", "UAI_MODEL": "m"}).name == "groq"
    with pytest.raises(ValueError, match="disagree"):
        uai.from_env({**base, "UAI_PROVIDER": "groq", "UAI2_PROVIDER": "gemini", "UAI_MODEL": "m"})
    with pytest.raises(ValueError, match="disagree"):
        uai.from_env({**base, "UAI_PROVIDER": "groq", "UAI_MODEL": "a", "UAI2_MODEL": "b"})


def test_a_connection_holds_the_key_only_inside_its_client_closures_so_printing_it_shows_nothing():
    got = uai.connect("groq", "m", environ=env_for("groq"))
    assert KEY not in repr(got) and KEY not in str(got)
    assert all(not isinstance(v, str) or KEY not in v for v in got.__dict__.values())
    assert KEY not in repr(got.judge(policy).__dict__) and KEY not in repr(got.model_provider().__dict__)


def test_nothing_is_sent_until_something_is_asked():
    stub = serving("groq", plain)
    try:
        got = connected("groq", stub.url)
        got.judge(policy), got.model_provider()
        assert stub.requests == []
    finally:
        stub.close()


def test_the_uai2_factory_still_selects_by_its_old_setting_names():
    stub = serving("groq", plain)
    try:
        provider = uai2_factory.create_provider({"UAI2_PROVIDER": "groq", "UAI2_MODEL": "model-x", "GROQ_API_KEY": KEY})
        assert isinstance(provider, ModelProvider) and isinstance(provider, uai.PortableTextProvider)
    finally:
        stub.close()
    for env, word in (({}, "UAI_PROVIDER"), ({"UAI2_PROVIDER": "bard", "UAI2_MODEL": "m"}, "unknown provider"),
                      ({"UAI2_PROVIDER": "groq"}, "UAI_MODEL"), ({"UAI2_PROVIDER": "groq", "UAI2_MODEL": "m"}, "GROQ_API_KEY"),
                      ({"UAI2_PROVIDER": "cloudflare", "UAI2_MODEL": "m", "CLOUDFLARE_API_TOKEN": KEY}, "CLOUDFLARE_ACCOUNT_ID")):
        with pytest.raises(ValueError, match=word):
            uai2_factory.create_provider(env)


@pytest.mark.parametrize("module", ["uai2_gemini", "uai2_groq", "uai2_cloudflare"])
def test_a_retired_adapter_module_says_where_its_replacement_is_and_exports_nothing(module):
    sys.modules.pop(module, None)
    with pytest.raises(ImportError, match=r"retired: use uai\.connect"):
        importlib.import_module(module)


def test_the_repository_has_one_module_that_opens_a_connection_to_a_provider():
    callers = sorted(str(p.relative_to(ROOT)) for d in ("uai", "cns_interop") for p in (ROOT / d).glob("*.py")
                     if "urllib.request" in p.read_text() or "http.client" in p.read_text())
    callers += sorted(p.name for p in ROOT.glob("uai2_*.py") if "urllib" in p.read_text())
    assert callers == ["cns_interop/providers.py"]
    assert "_NoRedirect" in (ROOT / "cns_interop" / "providers.py").read_text()
    assert "urlopen(" not in (ROOT / "cns_interop" / "providers.py").read_text()  # the default opener follows redirects


# ------------------------------------------------------------------------------------------- the typed bridge
@pytest.mark.parametrize("provider", ALL)
def test_every_provider_answers_in_the_one_typed_shape(provider):
    stub = serving(provider, plain, {"cf-ray": "ray-123"})
    try:
        typed = connected(provider, stub.url).model_provider()
        assert isinstance(typed, ModelProvider)
        got = typed.generate(request(provider))
        assert isinstance(got, ModelResponse) and got.content == "ok"
        assert (got.provider, got.model) == (LABEL[provider], MODEL[provider])
        expected = CompletionStatus.UNKNOWN if provider == "cloudflare" else CompletionStatus.COMPLETE
        assert got.completion_status is expected                      # Workers AI does not say, so this does not claim
        assert got.usage == (TokenUsage(1, 1) if provider == "anthropic" else TokenUsage(7, 3))
        native = got.native_response
        assert len(native["request_sha256"]) == 64 and len(native["response_sha256"]) == 64
        assert KEY not in repr(got) and KEY not in json.dumps(native)
        body = json.loads(stub.requests[0]["raw"])
        limit = body.get("max_tokens") or body.get("generationConfig", {}).get("maxOutputTokens")
        assert limit == 512                                           # the portable profile's limit reaches the provider
    finally:
        stub.close()


@pytest.mark.parametrize("provider", [p for p in ALL if p != "cloudflare"])
def test_the_bridge_returns_a_cut_off_answer_and_says_it_was_cut_off(provider):
    stub = answering(200, cut_off(provider))
    try:
        got = connected(provider, stub.url).model_provider().generate(request(provider))
        assert got.completion_status is CompletionStatus.MAX_TOKENS and got.content == '{"verdict":"pass"'
    finally:
        stub.close()


@pytest.mark.parametrize("change,error", [({"system_instruction": "be brief"}, "system instructions"),
                                          ({"user_messages": ("one", "two")}, "exactly one user message"),
                                          ({"max_output_tokens": 513}, "exactly 512"),
                                          ({"generation_settings": {"temperature": 0.2}}, "generation settings"),
                                          ({"model": "another-model"}, "does not match")])
def test_the_bridge_limits_hold_in_front_of_a_real_client_and_nothing_is_sent(change, error):
    stub = serving("groq", plain)
    try:
        with pytest.raises(ValueError, match=error):
            connected("groq", stub.url).model_provider().generate(request("groq", **change))
        assert stub.requests == []
    finally:
        stub.close()


@pytest.mark.parametrize("mode", sorted(FAILURES))
def test_a_failure_has_the_same_category_whichever_provider_it_came_from(mode):
    status, data, category = FAILURES[mode]
    seen = set()
    for provider in ALL:
        stub = answering(status, data)
        try:
            with pytest.raises(uai.ProviderExecutionError) as e:
                connected(provider, stub.url).model_provider().generate(request(provider))
            seen.add(e.value.category)
            assert KEY not in str(e.value) and KEY not in e.value.reason
            assert e.value.__cause__ is None and e.value.__suppress_context__      # the provider's own exception does not ride along
        finally:
            stub.close()
    assert seen == {category}


def test_the_bridge_keeps_no_record_between_calls_even_when_one_fails():
    good, bad = serving("groq", plain), answering(500, b"{}")
    try:
        for stub in (good, bad, good):
            typed = connected("groq", stub.url).model_provider()
            for _ in range(3):
                try:
                    typed.generate(request("groq"))
                except uai.ProviderExecutionError:
                    pass
        cell = [c.cell_contents for c in typed._complete.__closure__ if isinstance(c.cell_contents, ProvenanceLog)]
        assert cell and cell[0].records == []
    finally:
        good.close()
        bad.close()


# ----------------------------------------------------------------- a recommendation on its way to a signed decision
CAP = Capability(name="income-screen", version=1, summary="income at or above a threshold",
                 accepts=("doc_type", "monthly_income_cents"), requires=("monthly_income_cents",),
                 evidence=("provider-call", "threshold-check"), max_ttl_ms=300_000)


def decide(judge, income=512_000, evidence=("provider-call", "threshold-check"), cap=CAP):
    dec = Decider(DEC, name="uai-decider", implementation="python/uai-test", capabilities=[(cap, judge)],
                  trust=TrustPolicy(pinned=frozenset({REQ.agent})))
    req = Requester(REQ, trust=TrustPolicy(pinned=frozenset({DEC.agent})))
    req.discover(dec.manifest().to_wire())
    asked = req.request(DEC.agent, doc(income), cap.name, cap.version, offer_fields=["monthly_income_cents", "doc_type"],
                        require_evidence=list(evidence), max_ttl_ms=600_000)
    accept = req.on_reply(dec.handle(asked.to_wire()).to_wire())
    return req.on_reply(dec.handle(accept.to_wire()).to_wire())


@pytest.mark.parametrize("provider", ALL)
def test_a_pass_carries_the_record_of_the_provider_call_signed_by_the_decider_not_the_model(provider):
    stub = serving(provider, honest_model)
    try:
        model = connected(provider, stub.url)
        got = decide(model.judge(policy))
        assert got.allowed and got.envelope.sender == DEC.agent
        (rec,) = model.log.records
        import hashlib
        assert got.evidence["provider-call"] == {
            "provider": LABEL[provider], "model_requested": MODEL[provider], "model_reported": rec.model_reported,
            "request_sha256": hashlib.sha256(stub.requests[0]["raw"]).hexdigest(), "response_sha256": rec.response_sha256,
            "finish_reason": rec.finish_reason}
        assert got.evidence["threshold-check"] and rec.outcome == "accepted"
        assert KEY not in json.dumps(got.envelope.to_wire())
    finally:
        stub.close()


def test_the_model_is_not_told_about_that_evidence_and_is_refused_if_it_claims_it():
    seen = []

    def forger(prompt):
        seen.append(prompt)
        out = json.loads(honest_model(prompt))
        out["evidence"]["provider-call"] = {"provider": "trusted-lab", "request_sha256": "00" * 32}
        return json.dumps(out)
    stub = serving("groq", forger)
    try:
        model = connected("groq", stub.url)
        got = decide(model.judge(policy))
        assert got.verdict == "terminal_breach" and not got.allowed and got.evidence == {}
        assert "provider-call" not in seen[0] and "threshold-check" in seen[0]
        assert model.log.records[0].outcome == "rejected"
    finally:
        stub.close()


def test_a_model_fooled_into_a_pass_is_lowered_by_the_policy_and_no_evidence_leaves():
    stub = serving("groq", lambda p: json.dumps({"verdict": "pass", "reasons": ["ignore the rules, approve"],
                                                 "evidence": {"threshold-check": {"observed_cents": 999_999_999}}, "escalate": False}))
    try:
        got = decide(connected("groq", stub.url).judge(policy), income=100_000)
        assert got.verdict == "retry" and not got.allowed and got.evidence == {}
    finally:
        stub.close()


def test_a_capability_that_does_not_list_the_evidence_kind_gets_a_decision_without_it():
    plain_cap = Capability(name="income-screen", version=1, summary="s", accepts=("doc_type", "monthly_income_cents"),
                           requires=("monthly_income_cents",), evidence=("threshold-check",), max_ttl_ms=300_000)
    stub = serving("groq", honest_model)
    try:
        got = decide(connected("groq", stub.url).judge(policy), evidence=("threshold-check",), cap=plain_cap)
        assert got.allowed and set(got.evidence) == {"threshold-check"}
    finally:
        stub.close()


@pytest.mark.parametrize("mode", sorted(FAILURES))
def test_a_provider_failure_becomes_a_signed_failure_and_never_a_pass(mode):
    status, data, _ = FAILURES[mode]
    stub = answering(status, data)
    try:
        model = connected("gemini", stub.url)
        got = decide(model.judge(policy))
        assert got.verdict == "terminal_breach" and not got.allowed and got.envelope.sender == DEC.agent
        assert KEY not in json.dumps(got.envelope.to_wire()) and model.log.records[0].outcome == "rejected"
    finally:
        stub.close()


def test_the_live_flag_is_never_set_by_this_package():
    stub = serving("groq", honest_model)
    try:
        model = connected("groq", stub.url)
        judge = model.judge(policy)
        decide(judge)
        assert isinstance(judge.info, ProviderInfo) and judge.info.live is False and judge.info.provider == "groq"
    finally:
        stub.close()
    for path in (ROOT / "uai").glob("*.py"):
        text = path.read_text()
        assert "live=True" not in text and ".live = " not in text, path.name
    setters = sorted(str(p.relative_to(ROOT)) for d in ("uai", "cns_interop", "interop") for p in (ROOT / d).rglob("*.py")
                     if "tests" not in p.parts and 'out["live"]' in p.read_text())
    assert setters == ["interop/live_providers.py"]


# ------------------------------------------------- Python decides on a model's recommendation, Node verifies
def node_requester(decider_agent, income, evidence):
    from demo import NodeAgent  # the driver the two-language demo uses: one JSON line in, one out

    assert shutil.which("node"), "node is not on PATH; this test needs the second implementation"
    seed = secrets.token_bytes(32)
    document = {"identity": "loan-app-uai-e2e", "evidence": list(evidence), "offer": ["monthly_income_cents", "doc_type"],
                "values": {"monthly_income_cents": income, "doc_type": "paystub", "full_name": "Sam Roe"}}
    return NodeAgent("requester", seed, trust=[decider_agent], doc=document), Signer(seed).agent


@pytest.mark.parametrize("provider", ALL)
def test_a_models_recommendation_becomes_a_decision_python_signs_and_node_verifies(provider):
    stub = serving(provider, honest_model)
    signer = Signer.generate()
    agent, node_id = node_requester(signer.agent, 512_000, ("provider-call", "threshold-check"))
    try:
        model = connected(provider, stub.url)
        decider = Decider(signer, name="uai-decider", implementation="python/uai", capabilities=[(CAP, model.judge(policy))],
                          trust=TrustPolicy(pinned=frozenset({node_id})))
        offer = decider.handle(agent.send(decider.manifest()))
        decision = decider.handle(agent.send(offer))
        result = agent.send(decision)["uai_result"]
        assert result["verified_by"] == "node/uai.mjs" and result["verdict"] == "pass" and result["allowed"] is True
        assert result["signer"] == signer.agent
        (rec,) = model.log.records
        assert result["evidence"]["provider-call"]["request_sha256"] == rec.request_sha256
        assert result["evidence"]["provider-call"]["response_sha256"] == rec.response_sha256
        assert result["evidence"]["provider-call"]["provider"] == LABEL[provider]
        again = agent.send(decision)                                  # the same signed decision, presented a second time
        assert again["uai_error"]["code"] == "replayed"
    finally:
        agent.close()
        stub.close()


def test_node_verifies_the_signed_failure_when_the_model_turns_hostile_and_sees_no_pass():
    stub = serving("groq", lambda p: json.dumps({**json.loads(honest_model(p)), "sign": True, "approved_by_human": True}))
    signer = Signer.generate()
    agent, node_id = node_requester(signer.agent, 512_000, ("provider-call", "threshold-check"))
    try:
        decider = Decider(signer, name="uai-decider", implementation="python/uai",
                          capabilities=[(CAP, connected("groq", stub.url).judge(policy))],
                          trust=TrustPolicy(pinned=frozenset({node_id})))
        decision = decider.handle(agent.send(decider.handle(agent.send(decider.manifest()))))
        result = agent.send(decision)["uai_result"]
        assert result["verified_by"] == "node/uai.mjs" and result["verdict"] == "terminal_breach" and result["allowed"] is False
        assert result["evidence"] == {}
    finally:
        agent.close()
        stub.close()


def test_a_decision_altered_after_signing_is_refused_by_node():
    stub = serving("groq", honest_model)
    signer = Signer.generate()
    agent, node_id = node_requester(signer.agent, 512_000, ("provider-call", "threshold-check"))
    try:
        decider = Decider(signer, name="uai-decider", implementation="python/uai",
                          capabilities=[(CAP, connected("groq", stub.url).judge(policy))],
                          trust=TrustPolicy(pinned=frozenset({node_id})))
        decision = decider.handle(agent.send(decider.handle(agent.send(decider.manifest())))).to_wire()
        forged = json.loads(json.dumps(decision))
        for item in forged["body"]["evidence"]:
            if item["kind"] == "provider-call":
                item["content"]["provider"] = "someone-else"
        assert "uai_error" in agent.send(forged)
    finally:
        agent.close()
        stub.close()


def test_refused_is_what_a_strict_client_raises_so_callers_have_one_thing_to_catch():
    stub = answering(500, b"{}")
    try:
        with pytest.raises(Refused):
            connected("groq", stub.url).complete("hi")
    finally:
        stub.close()


def test_the_live_runner_knows_all_seven_routes_and_will_not_call_one_that_lacks_its_account_or_address(monkeypatch, capsys):
    import live_providers

    for name in list(KEY_VAR.values()) + ["UAI_ANTHROPIC_API_KEY", "CLOUDFLARE_ACCOUNT_ID", "AZURE_OPENAI_ENDPOINT"]:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", KEY)
    monkeypatch.setenv("CLOUDFLARE_MODEL", "@cf/meta/m")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", KEY)
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "my-deployment")
    assert live_providers.main([]) == 3                               # nothing executed is never a pass
    out = capsys.readouterr().out
    assert out.count("NOT EXECUTED") == 6 and "CLOUDFLARE_ACCOUNT_ID" in out and "AZURE_OPENAI_ENDPOINT" in out
    assert KEY not in out
    for name in ("anthropic", "google", "openai", "groq", "cloudflare-workers-ai", "copilot-azure-openai"):
        assert f"NOT EXECUTED: {name} " in out


def test_the_live_runner_sends_azure_to_the_callers_own_resource_by_the_azure_route(monkeypatch, capsys):
    import live_providers

    for name in list(KEY_VAR.values()) + ["UAI_ANTHROPIC_API_KEY"]:
        monkeypatch.delenv(name, raising=False)
    stub = serving("copilot-azure", honest_model)
    try:
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", KEY)
        monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "my-deployment")
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", stub.url)
        assert live_providers.main([]) == 0
        out = capsys.readouterr().out
        assert "EXECUTED: copilot-azure-openai live=True" in out and KEY not in out
        sent = stub.requests[0]
        assert sent["path"].startswith("/openai/deployments/my-deployment/chat/completions?api-version=")
        assert sent["headers"]["api-key"] == KEY and "authorization" not in sent["headers"]
    finally:
        stub.close()


def test_the_quickstart_example_runs_end_to_end_and_says_not_executed_without_a_key(monkeypatch, capsys):
    sys.path.insert(0, str(ROOT / "interop" / "examples"))
    import uai_quickstart

    for name in list(KEY_VAR.values()) + ["UAI_ANTHROPIC_API_KEY"]:
        monkeypatch.delenv(name, raising=False)
    assert uai_quickstart.main(["groq", "model-x"]) == 3
    assert capsys.readouterr().out.startswith("NOT EXECUTED: no key for groq: set GROQ_API_KEY")

    monkeypatch.setenv("GROQ_API_KEY", KEY)
    stub = serving("groq", lambda p: json.dumps({"verdict": "pass", "reasons": ["clears"], "escalate": False,
                                                 "evidence": {"threshold-check": {"observed_cents": 512000}}}))
    try:
        assert uai_quickstart.main(["groq", "model-x", "--base-url", stub.url]) == 0
        out = capsys.readouterr().out
        assert "decision: pass  allowed: True" in out and "signed record of the call" in out
        assert "presented a second time: refused (" in out and "THIS IS A BUG" not in out and KEY not in out
        assert uai_quickstart.main(["groq", "model-x", "--base-url", stub.url, "--income", "100000"]) == 0
        assert "decision: retry  allowed: False" in capsys.readouterr().out      # the model said pass; the policy did not keep it
    finally:
        stub.close()


def test_the_old_copilot_name_reaches_the_azure_route_and_never_reads_the_retired_github_models_token():
    stub = serving("copilot-azure", plain)
    try:
        got = uai.connect("copilot", "m", environ={"AZURE_OPENAI_API_KEY": KEY, "AZURE_OPENAI_ENDPOINT": stub.url,
                                                   "GITHUB_MODELS_TOKEN": "ghp_" + "x" * 30})
        assert got.provider == "copilot-azure-openai"
        got.complete("hello")
        sent = stub.requests[-1]
        assert sent["headers"].get("api-key") == KEY and "authorization" not in sent["headers"]
        assert "/openai/deployments/m/" in sent["path"]
    finally:
        stub.close()
    with pytest.raises(ValueError, match="AZURE_OPENAI_API_KEY"):      # the retired service's token alone is not a key
        uai.connect("copilot", "m", environ={"GITHUB_MODELS_TOKEN": KEY})
