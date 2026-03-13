# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Basic smoke tests for terok-shield."""

from unittest import mock

import pytest


def test_import() -> None:
    """Package is importable."""
    import terok_shield

    assert hasattr(terok_shield, "__version__")


def test_version_string() -> None:
    """Version is a non-empty string."""
    from terok_shield import __version__

    assert isinstance(__version__, str)
    assert len(__version__) > 0


def test_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    """CLI prints help without error."""
    from terok_shield.cli import main

    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    assert "terok-shield" in capsys.readouterr().out


def test_cli_no_command(capsys: pytest.CaptureFixture[str]) -> None:
    """CLI with no subcommand prints help and exits 0."""
    from terok_shield.cli import main

    with pytest.raises(SystemExit) as exc_info:
        main([])
    assert exc_info.value.code == 0
    assert "terok-shield" in capsys.readouterr().out


def test_cli_status(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI status subcommand prints mode info."""
    from terok_shield.cli import main

    mock_cls = mock.MagicMock()
    monkeypatch.setattr("terok_shield.cli._build_config", mock.Mock())
    monkeypatch.setattr("terok_shield.cli.Shield", mock_cls)
    mock_cls.return_value.status.return_value = {
        "mode": "standard",
        "audit_enabled": True,
        "profiles": [],
    }
    main(["status"])
    mock_cls.return_value.status.assert_called_once()
    assert "standard" in capsys.readouterr().out.lower()
