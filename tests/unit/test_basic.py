# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Basic smoke tests for terok-shield."""


def test_import() -> None:
    """Package is importable."""
    import terok_shield

    assert hasattr(terok_shield, "__version__")


def test_version_string() -> None:
    """Version is a non-empty string."""
    from terok_shield import __version__

    assert isinstance(__version__, str)
    assert len(__version__) > 0


def test_cli_help(capsys) -> None:
    """CLI prints help without error."""
    from terok_shield.cli import main

    try:
        main(["--help"])
    except SystemExit as e:
        assert e.code == 0
    captured = capsys.readouterr()
    assert "terok-shield" in captured.out


def test_cli_no_command(capsys) -> None:
    """CLI with no subcommand prints help and exits 0."""
    import pytest

    from terok_shield.cli import main

    with pytest.raises(SystemExit, match="0"):
        main([])
    captured = capsys.readouterr()
    assert "terok-shield" in captured.out


def test_cli_setup(capsys) -> None:
    """CLI setup subcommand completes without error."""
    from unittest import mock

    from terok_shield.cli import main

    with mock.patch("terok_shield.cli.Shield") as mock_cls:
        main(["setup"])
    mock_cls.return_value.setup.assert_called_once()
    captured = capsys.readouterr()
    assert "setup complete" in captured.out.lower()


def test_cli_status(capsys) -> None:
    """CLI status subcommand prints mode info."""
    from unittest import mock

    from terok_shield.cli import main

    with mock.patch("terok_shield.cli.Shield") as mock_cls:
        mock_cls.return_value.status.return_value = {
            "mode": "standard",
            "audit_enabled": True,
            "profiles": [],
            "log_files": [],
        }
        main(["status"])
    mock_cls.return_value.status.assert_called_once()
    captured = capsys.readouterr()
    assert "standard" in captured.out.lower()
