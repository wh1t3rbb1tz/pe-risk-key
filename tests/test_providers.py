"""Tests for pe_risk_key.providers (SPEC §3). No network access."""

import json
from types import SimpleNamespace

import httpx
import jsonschema
import pytest
from openai import APIStatusError, APITimeoutError, RateLimitError

from pe_risk_key.providers import ROLE_MODELS, SPARK_MODEL, ModelClient


def _response(status: int, retry_after: str | None = None) -> httpx.Response:
    headers = {}
    if retry_after is not None:
        headers["retry-after"] = str(retry_after)
    request = httpx.Request("POST", "https://api.meta.ai/v1/chat/completions")
    return httpx.Response(status, headers=headers, request=request)


def _rate_limit_error(retry_after: str | None = None) -> RateLimitError:
    return RateLimitError(
        "rate limited", response=_response(429, retry_after), body=None
    )


def _status_error(status: int) -> APIStatusError:
    return APIStatusError(
        f"http {status}", response=_response(status), body=None
    )


def _timeout_error() -> APITimeoutError:
    request = httpx.Request("POST", "https://api.meta.ai/v1/chat/completions")
    return APITimeoutError(request=request)


def _client(**overrides):
    overrides.setdefault("api_key", "test-key")
    overrides.setdefault("jitter", 0.0)
    return ModelClient(role="orchestrator", mode="standard", **overrides)


def test_role_model_routing():
    assert ROLE_MODELS == {
        "orchestrator": "muse-wonder-1.0",
        "document_analysis": "muse-wonder-1.0",
        "transcription": "muse-voice-transcribe-1.0",
        "claim_extraction": "muse-wonder-1.0",
        "crosscheck": "muse-wonder-1.0",
        "narrative": "muse-wonder-1.0",
        "public_records": "muse-spark-1.3",
    }
    assert SPARK_MODEL == "muse-spark-1.3"
    assert ROLE_MODELS["public_records"] == SPARK_MODEL
    for role, model in ROLE_MODELS.items():
        client = ModelClient(role=role, mode="standard", api_key="test-key")  # type: ignore[arg-type]
        assert client.model == model
        assert client.base_url == "https://api.meta.ai/v1"
        assert client.provider == "meta_model_api"


def test_confidential_mode_is_stub():
    with pytest.raises(NotImplementedError):
        ModelClient(role="orchestrator", mode="confidential", api_key="x")


def test_unknown_role_rejected():
    with pytest.raises(ValueError, match="Unknown role"):
        ModelClient(role="nope", mode="standard", api_key="x")  # type: ignore[arg-type]


def test_unknown_mode_rejected():
    with pytest.raises(ValueError, match="Unknown mode"):
        ModelClient(role="orchestrator", mode="nope", api_key="x")  # type: ignore[arg-type]


def test_missing_api_key_rejected(monkeypatch):
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="MODEL_API_KEY"):
        ModelClient(role="orchestrator", mode="standard")


def test_contributor_model_rejected_standard():
    with pytest.raises(ValueError, match="contributor"):
        ModelClient(
            role="orchestrator",
            mode="standard",
            api_key="x",
            model="muse-wonder-1.0-contributor",
        )


def test_contributor_model_rejected_confidential():
    # Guard fires before the confidential-mode stub: forbidden in any mode.
    with pytest.raises(ValueError, match="contributor"):
        ModelClient(
            role="document_analysis",
            mode="confidential",
            api_key="x",
            model="muse-spark-1.3-contributor",
        )


def test_chat_retries_on_429_then_succeeds(monkeypatch):
    client = _client(max_retries=3, backoff_base=1.0)
    sleeps: list[float] = []
    monkeypatch.setattr("pe_risk_key.providers.time.sleep", sleeps.append)
    calls = {"n": 0}

    def fake_create(**kwargs):
        calls["n"] += 1
        if calls["n"] < 3:
            raise _rate_limit_error()
        return "ok"

    monkeypatch.setattr(client.client.chat.completions, "create", fake_create)
    assert client.chat([{"role": "user", "content": "hi"}]) == "ok"
    assert calls["n"] == 3
    assert sleeps == [1.0, 2.0]  # exponential backoff, jitter disabled


def test_retry_honors_retry_after(monkeypatch):
    client = _client(max_retries=1, backoff_base=0.5)
    sleeps: list[float] = []
    monkeypatch.setattr("pe_risk_key.providers.time.sleep", sleeps.append)

    def fake_create(**kwargs):
        raise _rate_limit_error(retry_after="30")

    monkeypatch.setattr(client.client.chat.completions, "create", fake_create)
    with pytest.raises(RateLimitError):
        client.chat([{"role": "user", "content": "hi"}])
    assert sleeps == [30.0]  # Retry-After wins over the 0.5s backoff


def test_non_429_errors_not_retried(monkeypatch):
    client = _client(max_retries=3)
    sleeps: list[float] = []
    monkeypatch.setattr("pe_risk_key.providers.time.sleep", sleeps.append)
    calls = {"n": 0}

    def fake_create(**kwargs):
        calls["n"] += 1
        raise _status_error(403)

    monkeypatch.setattr(client.client.chat.completions, "create", fake_create)
    with pytest.raises(APIStatusError):
        client.chat([{"role": "user", "content": "hi"}])
    assert calls["n"] == 1
    assert sleeps == []


def test_retry_budget_exhausted_reraises(monkeypatch):
    client = _client(max_retries=2, backoff_base=0.1)
    sleeps: list[float] = []
    monkeypatch.setattr("pe_risk_key.providers.time.sleep", sleeps.append)
    calls = {"n": 0}

    def fake_create(**kwargs):
        calls["n"] += 1
        raise _rate_limit_error()

    monkeypatch.setattr(client.client.chat.completions, "create", fake_create)
    with pytest.raises(RateLimitError):
        client.chat([{"role": "user", "content": "hi"}])
    assert calls["n"] == 3  # initial attempt + 2 retries
    assert len(sleeps) == 2


def _http_response(
    status: int, json_body: dict | None = None, retry_after: str | None = None
) -> httpx.Response:
    headers = {}
    if retry_after is not None:
        headers["retry-after"] = retry_after
    request = httpx.Request("POST", "https://api.meta.ai/v1/asr/transcribe")
    return httpx.Response(status, json=json_body, headers=headers, request=request)


def _transcribe_client(**overrides):
    overrides.setdefault("api_key", "test-key")
    overrides.setdefault("jitter", 0.0)
    return ModelClient(role="transcription", mode="standard", **overrides)


def test_transcribe_posts_multipart_asr_request(monkeypatch):
    client = _transcribe_client()
    captured: dict = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return _http_response(200, {"transcript": "hi", "turns": []})

    monkeypatch.setattr("httpx.post", fake_post)
    result = client.transcribe(b"RIFFfake", filename="meeting.wav", session_id="s1")
    assert result == {"transcript": "hi", "turns": []}
    assert captured["url"] == "https://api.meta.ai/v1/asr/transcribe"
    assert captured["params"] == {"sessionId": "s1"}
    assert captured["headers"] == {"Authorization": "Bearer test-key"}
    req_name, req_body, req_type = captured["files"]["request"]
    assert req_name is None
    assert req_type == "application/json"
    assert json.loads(req_body) == {
        "mode": "DIARIZATION",
        "model": "muse-voice-transcribe-1.0",
        "audioEncoding": "WAV",
    }
    audio_name, audio_body, audio_type = captured["files"]["audio"]
    assert (audio_name, audio_body, audio_type) == ("meeting.wav", b"RIFFfake", "audio/wav")


def test_transcribe_reads_audio_from_path(monkeypatch, tmp_path):
    client = _transcribe_client()
    wav = tmp_path / "interview.wav"
    wav.write_bytes(b"RIFFfake")
    captured: dict = {}

    def fake_post(url, **kwargs):
        captured.update(kwargs)
        return _http_response(200, {"transcript": "hi"})

    monkeypatch.setattr("httpx.post", fake_post)
    assert client.transcribe(wav) == {"transcript": "hi"}
    audio_name, audio_body, _ = captured["files"]["audio"]
    assert audio_name == "interview.wav"
    assert audio_body == b"RIFFfake"
    assert captured["params"]["sessionId"]  # default session id generated


def test_transcribe_retries_on_429(monkeypatch):
    client = _transcribe_client(max_retries=1, backoff_base=1.0)
    sleeps: list[float] = []
    monkeypatch.setattr("pe_risk_key.providers.time.sleep", sleeps.append)
    calls = {"n": 0}

    def fake_post(url, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return _http_response(429)
        return _http_response(200, {"transcript": "hi"})

    monkeypatch.setattr("httpx.post", fake_post)
    assert client.transcribe(b"RIFFfake") == {"transcript": "hi"}
    assert calls["n"] == 2
    assert sleeps == [1.0]


def test_transcribe_retry_honors_retry_after(monkeypatch):
    client = _transcribe_client(max_retries=1, backoff_base=0.5)
    sleeps: list[float] = []
    monkeypatch.setattr("pe_risk_key.providers.time.sleep", sleeps.append)

    def fake_post(url, **kwargs):
        return _http_response(429, retry_after="30")

    monkeypatch.setattr("httpx.post", fake_post)
    with pytest.raises(httpx.HTTPStatusError):
        client.transcribe(b"RIFFfake")
    assert sleeps == [30.0]


def test_transcribe_non_429_not_retried(monkeypatch):
    client = _transcribe_client(max_retries=3)
    sleeps: list[float] = []
    monkeypatch.setattr("pe_risk_key.providers.time.sleep", sleeps.append)
    calls = {"n": 0}

    def fake_post(url, **kwargs):
        calls["n"] += 1
        return _http_response(403)

    monkeypatch.setattr("httpx.post", fake_post)
    with pytest.raises(httpx.HTTPStatusError):
        client.transcribe(b"RIFFfake")
    assert calls["n"] == 1
    assert sleeps == []


def _chat_response(content: str, usage=None):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
        usage=usage,
    )


def test_chat_accumulates_token_usage(monkeypatch):
    client = _client()

    def fake_create(**kwargs):
        return _chat_response(
            "hi",
            usage=SimpleNamespace(
                prompt_tokens=10,
                completion_tokens=5,
                prompt_tokens_details=SimpleNamespace(cached_tokens=2),
            ),
        )

    monkeypatch.setattr(client.client.chat.completions, "create", fake_create)
    client.chat([{"role": "user", "content": "hi"}])
    client.chat([{"role": "user", "content": "hi"}])
    assert client.total_usage == {
        "prompt_tokens": 20,
        "completion_tokens": 10,
        "cached_tokens": 4,
    }


THING_SCHEMA = {
    "type": "object",
    "properties": {"a": {"type": "string"}},
    "required": ["a"],
    "additionalProperties": False,
}


def test_chat_json_sends_json_schema_request(monkeypatch):
    client = _client()
    captured: dict = {}

    def fake_create(*, messages, **kwargs):
        captured["messages"] = messages
        captured.update(kwargs)
        return _chat_response('{"a": "ok"}')

    monkeypatch.setattr(client.client.chat.completions, "create", fake_create)
    result = client.chat_json(
        [{"role": "user", "content": "hi"}],
        schema=THING_SCHEMA,
        schema_name="Thing",
    )
    assert result == {"a": "ok"}
    assert captured["response_format"] == {
        "type": "json_schema",
        "json_schema": {"name": "Thing", "schema": THING_SCHEMA, "strict": True},
    }
    assert captured["model"] == "muse-wonder-1.0"


def test_chat_json_falls_back_to_json_object(monkeypatch):
    client = _client()
    captured: dict = {}

    def fake_create(*, messages, **kwargs):
        captured.update(kwargs)
        return _chat_response('{"a": 1}')

    monkeypatch.setattr(client.client.chat.completions, "create", fake_create)
    assert client.chat_json([{"role": "user", "content": "hi"}]) == {"a": 1}
    assert captured["response_format"] == {"type": "json_object"}


def test_chat_json_retries_once_on_invalid_output(monkeypatch):
    client = _client()
    calls: list = []
    contents = ['{"b": "wrong"}', '{"a": "fixed"}']

    def fake_create(*, messages, **kwargs):
        calls.append({"messages": messages, **kwargs})
        return _chat_response(contents[len(calls) - 1])

    monkeypatch.setattr(client.client.chat.completions, "create", fake_create)
    messages = [{"role": "user", "content": "hi"}]
    result = client.chat_json(messages, schema=THING_SCHEMA, schema_name="T")
    assert result == {"a": "fixed"}
    assert len(calls) == 2
    assert calls[0]["messages"] == messages
    retry_messages = calls[1]["messages"]
    assert retry_messages[0] == messages[0]
    assert retry_messages[1] == {"role": "assistant", "content": '{"b": "wrong"}'}
    assert retry_messages[2]["role"] == "user"
    assert "'a' is a required property" in retry_messages[2]["content"]
    assert calls[1]["response_format"]["type"] == "json_schema"
    assert messages == [{"role": "user", "content": "hi"}]  # not mutated


def test_chat_json_raises_after_second_failure(monkeypatch):
    client = _client()
    calls: list = []

    def fake_create(*, messages, **kwargs):
        calls.append(messages)
        return _chat_response('{"b": 1}')

    monkeypatch.setattr(client.client.chat.completions, "create", fake_create)
    with pytest.raises(jsonschema.ValidationError, match="required property"):
        client.chat_json(
            [{"role": "user", "content": "hi"}],
            schema=THING_SCHEMA,
            schema_name="T",
        )
    assert len(calls) == 2


def test_chat_retries_timeout_then_succeeds(monkeypatch, capsys):
    client = _client(backoff_base=1.0)
    sleeps: list[float] = []
    monkeypatch.setattr("pe_risk_key.providers.time.sleep", sleeps.append)
    calls = {"n": 0}

    def fake_create(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _timeout_error()
        return "ok"

    monkeypatch.setattr(client.client.chat.completions, "create", fake_create)
    assert client.chat([{"role": "user", "content": "hi"}]) == "ok"
    assert calls["n"] == 2
    assert sleeps == [1.0]
    err = capsys.readouterr().err
    assert "retry 1" in err and "timeout" in err


def test_chat_retries_503_then_succeeds(monkeypatch, capsys):
    client = _client(backoff_base=0.5)
    sleeps: list[float] = []
    monkeypatch.setattr("pe_risk_key.providers.time.sleep", sleeps.append)
    calls = {"n": 0}

    def fake_create(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _status_error(503)
        return "ok"

    monkeypatch.setattr(client.client.chat.completions, "create", fake_create)
    assert client.chat([{"role": "user", "content": "hi"}]) == "ok"
    assert calls["n"] == 2
    assert sleeps == [0.5]
    assert "HTTP 503" in capsys.readouterr().err


def test_transient_retries_exhausted_reraises(monkeypatch):
    client = _client(backoff_base=0.1)  # default: 2 transient retries
    sleeps: list[float] = []
    monkeypatch.setattr("pe_risk_key.providers.time.sleep", sleeps.append)
    calls = {"n": 0}

    def fake_create(**kwargs):
        calls["n"] += 1
        raise _status_error(503)

    monkeypatch.setattr(client.client.chat.completions, "create", fake_create)
    with pytest.raises(APIStatusError):
        client.chat([{"role": "user", "content": "hi"}])
    assert calls["n"] == 3  # initial attempt + 2 retries
    assert len(sleeps) == 2


def test_400_not_retried(monkeypatch):
    client = _client(max_retries=3)
    sleeps: list[float] = []
    monkeypatch.setattr("pe_risk_key.providers.time.sleep", sleeps.append)
    calls = {"n": 0}

    def fake_create(**kwargs):
        calls["n"] += 1
        raise _status_error(400)

    monkeypatch.setattr(client.client.chat.completions, "create", fake_create)
    with pytest.raises(APIStatusError):
        client.chat([{"role": "user", "content": "hi"}])
    assert calls["n"] == 1
    assert sleeps == []


def test_reasoning_effort_passthrough(monkeypatch):
    client = _client()
    captured: dict = {}

    def fake_create(*, messages, **kwargs):
        captured.update(kwargs)
        return _chat_response('{"a": "ok"}')

    monkeypatch.setattr(client.client.chat.completions, "create", fake_create)
    client.chat([{"role": "user", "content": "hi"}], reasoning_effort="medium")
    assert captured["reasoning_effort"] == "medium"
    client.chat_json(
        [{"role": "user", "content": "hi"}],
        schema=THING_SCHEMA,
        schema_name="T",
        reasoning_effort="low",
    )
    assert captured["reasoning_effort"] == "low"


def test_timeout_config_default_env_and_override(monkeypatch):
    monkeypatch.delenv("MODEL_TIMEOUT_SECONDS", raising=False)
    assert _client()._timeout == 300.0
    monkeypatch.setenv("MODEL_TIMEOUT_SECONDS", "45")
    assert _client()._timeout == 45.0
    assert _client(timeout=10.0)._timeout == 10.0


def test_responses_search_sends_web_search_tool(monkeypatch):
    client = ModelClient(role="public_records", mode="standard", api_key="k")
    assert client.model == SPARK_MODEL
    assert "-contributor" not in client.model
    captured: dict = {}

    def fake_create(*, input, **kwargs):
        captured["input"] = input
        captured.update(kwargs)
        return SimpleNamespace(
            output=[],
            usage=SimpleNamespace(input_tokens=30, output_tokens=7),
        )

    monkeypatch.setattr(client.client.responses, "create", fake_create)
    client.responses_search("Acme data breach", instructions="rules")
    assert captured["input"] == "Acme data breach"
    assert captured["model"] == "muse-spark-1.3"
    assert captured["tools"] == [{"type": "web_search"}]
    assert captured["instructions"] == "rules"
    assert client.total_usage["prompt_tokens"] == 30
    assert client.total_usage["completion_tokens"] == 7
