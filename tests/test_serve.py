# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for scripts/serve.py bind guard and key warning. No network."""

import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_script(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "serve_script", ROOT / "scripts" / "serve.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    run = Mock()
    monkeypatch.setattr(module.uvicorn, "run", run)
    return module, run


def test_refuses_non_loopback_without_override(monkeypatch, capsys):
    script, run = _load_script(monkeypatch)
    monkeypatch.delenv("PE_RISK_KEY_ALLOW_REMOTE", raising=False)
    with pytest.raises(SystemExit) as exc:
        script.main(["--host", "0.0.0.0"])
    assert exc.value.code == 2
    run.assert_not_called()
    assert "localhost only" in capsys.readouterr().err


def test_allows_remote_with_opt_in(monkeypatch):
    script, run = _load_script(monkeypatch)
    monkeypatch.setenv("PE_RISK_KEY_ALLOW_REMOTE", "1")
    monkeypatch.setenv("MODEL_API_KEY", "test-key")
    script.main(["--host", "0.0.0.0", "--port", "9000"])
    run.assert_called_once()
    assert run.call_args.kwargs["host"] == "0.0.0.0"
    assert run.call_args.kwargs["port"] == 9000


def test_warns_when_key_missing(monkeypatch, capsys):
    script, run = _load_script(monkeypatch)
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    script.main([])
    run.assert_called_once()
    assert "MODEL_API_KEY is not set" in capsys.readouterr().err
