"""Model routing and providers (SPEC §3).

One provider interface, OpenAI-compatible, selected by config::

    client = ModelClient(role="orchestrator", mode="standard")
    reply = client.chat([{"role": "user", "content": "Summarize the signals."}])

Secrets come from the environment (``.env`` is loaded on import):

- standard mode:     ``MODEL_API_KEY``      → Meta Model API
- confidential mode: ``BASETEN_API_KEY``    → partner inference (stub)

Transcription is the one non-OpenAI-shaped call: it POSTs multipart
audio to ``/v1/asr/transcribe`` per
https://dev.meta.ai/docs/speech-to-text.
"""

from __future__ import annotations

import json
import os
import random
import sys
import time
import uuid
from pathlib import Path
from typing import Any, BinaryIO, Literal

import httpx
import jsonschema
from dotenv import load_dotenv
from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    OpenAI,
    RateLimitError,
)

load_dotenv()

Role = Literal[
    "orchestrator",
    "document_analysis",
    "transcription",
    "claim_extraction",
    "crosscheck",
    "narrative",
    "public_records",
]
Mode = Literal["standard", "confidential"]

STANDARD_BASE_URL = "https://api.meta.ai/v1"
STANDARD_PROVIDER = "meta_model_api"

WONDER_MODEL = "muse-wonder-1.0"
VOICE_MODEL = "muse-voice-transcribe-1.0"
# Standard-mode Muse Wonder prices per 1M tokens, per
# https://dev.meta.ai/docs/pricing-rate-limits.
WONDER_USD_PER_MTOK = {"input": 4.0, "cached": 0.20, "output": 20.0}
# Cheap sub-tasks: grounded public-records searches.
SPARK_MODEL = "muse-spark-1.3"

# SPEC §3: muse-wonder-1.0 for agent/analysis work,
# muse-voice-transcribe-1.0 for transcription, muse-spark-1.3 for
# search-grounded public-records lookups.
ROLE_MODELS: dict[str, str] = {
    "orchestrator": WONDER_MODEL,
    "document_analysis": WONDER_MODEL,
    "transcription": VOICE_MODEL,
    "claim_extraction": WONDER_MODEL,
    "crosscheck": WONDER_MODEL,
    "narrative": WONDER_MODEL,
    "public_records": SPARK_MODEL,
}

_RETRYABLE_STATUS = 429
_TRANSIENT_STATUSES = frozenset({500, 502, 503, 504})

# Sentinel for "content held no parseable JSON at all" (distinct from a
# parsed JSON null, which still goes through schema validation).
_UNPARSED: Any = object()


class ModelClient:
    """Thin wrapper around the OpenAI SDK with role/mode routing and 429 retry.

    Args:
        role: Which pipeline role this client serves. Selects the model.
        mode: ``"standard"`` (Meta Model API) or ``"confidential"``
            (partner open-weight inference; stub, raises ``NotImplementedError``).
            Defaults to ``PE_RISK_KEY_MODE``, falling back to ``"standard"``.
        api_key: Explicit API key; defaults to the mode's env var.
        base_url: Explicit base URL; defaults to the mode's base URL.
        model: Explicit model; defaults to the role's model.
        timeout: Per-request timeout in seconds. Defaults to
            ``MODEL_TIMEOUT_SECONDS``, falling back to 300.
        max_retries: Retries on HTTP 429 after the initial attempt.
        transient_retries: Retries on timeouts, connection errors, and
            retryable 5xx after the initial attempt.
        backoff_base: Base delay in seconds; attempt ``n`` waits
            ``backoff_base * 2**n`` plus jitter.
        backoff_cap: Maximum backoff delay in seconds (before jitter).
        jitter: Upper bound of uniform ``[0, jitter)`` seconds added per wait.
    """

    def __init__(
        self,
        role: Role,
        mode: Mode | None = None,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
        max_retries: int = 5,
        transient_retries: int = 2,
        backoff_base: float = 1.0,
        backoff_cap: float = 60.0,
        jitter: float = 1.0,
    ) -> None:
        if role not in ROLE_MODELS:
            raise ValueError(
                f"Unknown role {role!r}; expected one of {sorted(ROLE_MODELS)}."
            )
        resolved_model = model or ROLE_MODELS[role]
        if "-contributor" in resolved_model:
            raise ValueError(
                f"Refusing model {resolved_model!r}: '-contributor' variants "
                "must never process target data (SPEC §3)."
            )
        resolved_mode = mode or os.getenv("PE_RISK_KEY_MODE", "standard")
        if resolved_mode == "confidential":
            raise NotImplementedError(
                "Confidential mode (open-weight inference on Baseten/Modal/"
                "Fireworks, model meta-models/muse-spark-open-1026) is not "
                "wired up yet; partner endpoint lands Nov 2 per SPEC §8."
            )
        if resolved_mode != "standard":
            raise ValueError(
                f"Unknown mode {resolved_mode!r}; expected 'standard' or "
                "'confidential'."
            )

        resolved_key = api_key or os.getenv("MODEL_API_KEY")
        if not resolved_key:
            raise RuntimeError(
                "MODEL_API_KEY is not set; add it to .env (see .env.example)."
            )

        self.role = role
        self.mode: Mode = "standard"
        self.provider = STANDARD_PROVIDER
        self.base_url = base_url or STANDARD_BASE_URL
        self.model = resolved_model
        self.max_retries = max_retries
        self.transient_retries = transient_retries
        self.backoff_base = backoff_base
        self.backoff_cap = backoff_cap
        self.jitter = jitter
        self.total_usage = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "cached_tokens": 0,
        }
        self._api_key = resolved_key
        self._timeout = (
            timeout
            if timeout is not None
            else float(os.getenv("MODEL_TIMEOUT_SECONDS", "300"))
        )
        # SDK-level retries are disabled: this class owns the retry policy
        # (exponential backoff + jitter, honoring Retry-After) below.
        self._client = OpenAI(
            api_key=resolved_key,
            base_url=self.base_url,
            timeout=self._timeout,
            max_retries=0,
        )

    @property
    def client(self) -> OpenAI:
        """The underlying OpenAI SDK client (retries disabled; use methods)."""
        return self._client

    def _wait(self, attempt: int, retry_after: float | None) -> None:
        delay = min(self.backoff_cap, self.backoff_base * (2**attempt))
        delay += random.uniform(0, self.jitter)
        if retry_after is not None:
            delay = max(delay, retry_after)
        time.sleep(delay)

    @staticmethod
    def _retry_after_seconds(exc: Exception) -> float | None:
        try:
            raw = exc.response.headers.get("retry-after")  # type: ignore[attr-defined]
        except Exception:  # defensive: never fail retry handling on headers
            return None
        if raw is None:
            return None
        try:
            return max(0.0, float(raw))
        except ValueError:
            return None

    def _log_retry(self, reason: str, attempt: int) -> None:
        print(
            f"[ModelClient:{self.role}] retry {attempt + 1} ({reason})",
            file=sys.stderr,
        )

    def _classify_retry(
        self, exc: Exception
    ) -> tuple[str, str, float | None] | None:
        """Classify a failure as (budget, reason, retry_after).

        Returns ``None`` for failures that must not be retried (4xx other
        than 429). ``RateLimitError`` is checked before ``APIStatusError``,
        its parent.
        """
        if isinstance(exc, RateLimitError):
            return ("rate", "HTTP 429", self._retry_after_seconds(exc))
        if isinstance(exc, APIStatusError):
            if exc.status_code == _RETRYABLE_STATUS:
                return ("rate", "HTTP 429", self._retry_after_seconds(exc))
            if exc.status_code in _TRANSIENT_STATUSES:
                return (
                    "transient",
                    f"HTTP {exc.status_code}",
                    self._retry_after_seconds(exc),
                )
            return None
        if isinstance(exc, APITimeoutError):
            return ("transient", "timeout", None)
        if isinstance(exc, APIConnectionError):
            return ("transient", "connection error", None)
        if isinstance(exc, httpx.HTTPStatusError):
            status = exc.response.status_code
            if status == _RETRYABLE_STATUS:
                return ("rate", "HTTP 429", self._retry_after_seconds(exc))
            if status in _TRANSIENT_STATUSES:
                return (
                    "transient",
                    f"HTTP {status}",
                    self._retry_after_seconds(exc),
                )
            return None
        return None

    def _with_retry(self, func: Any, *args: Any, **kwargs: Any) -> Any:
        attempts = {"rate": 0, "transient": 0}
        budgets = {"rate": self.max_retries, "transient": self.transient_retries}
        while True:
            try:
                return func(*args, **kwargs)
            except (
                RateLimitError,
                APIStatusError,
                APITimeoutError,
                APIConnectionError,
                httpx.HTTPStatusError,
            ) as exc:
                classified = self._classify_retry(exc)
                if classified is None:
                    raise
                kind, reason, retry_after = classified
                if attempts[kind] >= budgets[kind]:
                    raise
                self._log_retry(reason, attempts[kind])
                self._wait(attempts[kind], retry_after)
                attempts[kind] += 1

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        reasoning_effort: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """Chat completion with the role's model; retries on 429/transients.

        ``reasoning_effort`` is passed through as the top-level request
        parameter (minimal/low/medium/high/xhigh/max per
        https://dev.meta.ai/docs/reasoning). Token usage accumulates on
        ``self.total_usage`` across calls.
        """
        kwargs.setdefault("model", self.model)
        if reasoning_effort is not None:
            kwargs["reasoning_effort"] = reasoning_effort
        response = self._with_retry(
            self._client.chat.completions.create, messages=messages, **kwargs
        )
        self._accumulate_usage(response)
        return response

    def _accumulate_usage(self, response: Any) -> None:
        usage = getattr(response, "usage", None)
        if usage is None:
            return
        details = getattr(usage, "prompt_tokens_details", None)
        # Chat completions report prompt/completion tokens; the Responses
        # API reports input/output tokens.
        self.total_usage["prompt_tokens"] += (
            getattr(usage, "prompt_tokens", 0)
            or getattr(usage, "input_tokens", 0)
            or 0
        )
        self.total_usage["completion_tokens"] += (
            getattr(usage, "completion_tokens", 0)
            or getattr(usage, "output_tokens", 0)
            or 0
        )
        self.total_usage["cached_tokens"] += (
            getattr(details, "cached_tokens", 0) or 0
        )

    def responses_search(
        self,
        query: str,
        *,
        instructions: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """One grounded search via the Responses API; retries on 429/transients.

        Sends ``tools=[{"type": "web_search"}]`` per
        https://dev.meta.ai/docs/search-grounding: the model decides
        whether to search, and citations come back as ``url_citation``
        annotations on ``output_text`` blocks. Token usage accumulates
        on ``self.total_usage`` across calls.
        """
        kwargs.setdefault("model", self.model)
        kwargs.setdefault("tools", [{"type": "web_search"}])
        if instructions is not None:
            kwargs["instructions"] = instructions
        response = self._with_retry(
            self._client.responses.create, input=query, **kwargs
        )
        self._accumulate_usage(response)
        return response

    @staticmethod
    def _salvage_last_json_object(content: str) -> dict | None:
        """Last top-level ``{...}`` in ``content`` that parses, if any.

        Scans every ``{`` as a candidate start; a candidate counts as
        top-level when no other candidate's span strictly contains it.
        Returns the rightmost top-level object, else ``None``.
        """
        decoder = json.JSONDecoder()
        spans: list[tuple[int, int, dict]] = []
        for start in range(len(content)):
            if content[start] != "{":
                continue
            try:
                obj, end = decoder.raw_decode(content, start)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                spans.append((start, end, obj))
        top_level = [
            span
            for span in spans
            if not any(
                other[0] < span[0] and span[1] <= other[1]
                for other in spans
                if other is not span
            )
        ]
        return top_level[-1][2] if top_level else None

    def chat_json(
        self,
        messages: list[dict[str, Any]],
        *,
        schema: dict[str, Any] | None = None,
        schema_name: str = "response",
        reasoning_effort: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """Chat completion parsed as JSON.

        With ``schema`` (build it with ``pe_risk_key.schemas`` so it
        satisfies the strict subset), requests schema-constrained output
        via ``response_format={"type": "json_schema", ...}`` with
        ``strict: true``, validates the parsed response against ``schema``,
        and retries once with the validation errors appended on failure.
        If an attempt's content is not pure JSON, the last top-level
        JSON object is salvaged and validated before counting it a
        failure. Raises the validation error if the second attempt also
        fails. Without ``schema``, falls back to unconstrained
        ``json_object``. ``reasoning_effort`` passes through to :meth:`chat`.
        """
        if reasoning_effort is not None:
            kwargs["reasoning_effort"] = reasoning_effort
        if schema is None:
            kwargs["response_format"] = {"type": "json_object"}
            response = self.chat(messages, **kwargs)
            return json.loads(response.choices[0].message.content)

        kwargs["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": schema_name, "schema": schema, "strict": True},
        }
        validator = jsonschema.Draft202012Validator(schema)
        attempt_messages = list(messages)
        for attempt in range(2):
            response = self.chat(attempt_messages, **kwargs)
            content = response.choices[0].message.content
            try:
                parsed: Any = json.loads(content)
            except json.JSONDecodeError:
                # Defensive: narration around the JSON ("I'll search…")
                # fails strict parsing, so try the last top-level JSON
                # object in the content before counting this a failure.
                salvaged = self._salvage_last_json_object(content)
                if salvaged is None:
                    unparsed: Any = _UNPARSED
                else:
                    unparsed = salvaged
            else:
                unparsed = parsed
            if unparsed is _UNPARSED:
                errors = [f"(invalid JSON): {content[:200]}"]
            else:
                failures = sorted(
                    validator.iter_errors(unparsed), key=lambda e: e.json_path
                )
                if not failures:
                    return unparsed
                errors = [f"{e.json_path}: {e.message}" for e in failures]
                if attempt == 1:
                    raise failures[0]
            if attempt == 1:
                raise ValueError(
                    "Second structured-output attempt was not valid JSON."
                )
            shown = errors[:10]
            if len(errors) > 10:
                shown.append(f"({len(errors) - 10} more errors)")
            attempt_messages = [
                *attempt_messages,
                {"role": "assistant", "content": content},
                {
                    "role": "user",
                    "content": (
                        "Your previous response did not match the required "
                        "JSON schema:\n"
                        + "\n".join(f"- {e}" for e in shown)
                        + "\nReturn only corrected JSON matching the schema."
                    ),
                },
            ]
        raise AssertionError("unreachable")  # pragma: no cover

    def transcribe(
        self,
        audio: str | Path | bytes | BinaryIO,
        *,
        filename: str | None = None,
        asr_mode: str = "DIARIZATION",
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Transcribe audio via ``POST /v1/asr/transcribe``; retries on 429.

        Multipart upload per https://dev.meta.ai/docs/speech-to-text: a JSON
        ``request`` part (mode, model, audioEncoding) plus the ``audio`` part.
        ``asr_mode`` defaults to ``DIARIZATION`` (SPEC §4.3: diarization on).
        Returns the parsed JSON response (``transcript``, ``turns``, ...).

        The endpoint accepts only RIFF/WAVE mono 16-bit PCM at 16/24 kHz;
        convert other formats first, e.g.::
            ffmpeg -i input.m4a -ac 1 -ar 24000 -c:a pcm_s16le -map_metadata -1 output.wav
        """
        data = audio.read() if hasattr(audio, "read") else audio
        if isinstance(data, (str, Path)):
            path = Path(data)
            resolved_filename = filename or path.name
            data = path.read_bytes()
        else:
            resolved_filename = filename or "audio.wav"
        settings = {
            "mode": asr_mode,
            "model": self.model,
            "audioEncoding": "WAV",
        }

        def _post() -> dict[str, Any]:
            response = httpx.post(
                f"{self.base_url}/asr/transcribe",
                params={"sessionId": session_id or uuid.uuid4().hex},
                headers={"Authorization": f"Bearer {self._api_key}"},
                files={
                    "request": (None, json.dumps(settings), "application/json"),
                    "audio": (resolved_filename, data, "audio/wav"),
                },
                timeout=self._timeout,
            )
            response.raise_for_status()
            return response.json()

        return self._with_retry(_post)
