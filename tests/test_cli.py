from pathlib import Path

import pytest

from stellargate.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def good_config(tmp_path):
    path = tmp_path / "stellargate.yaml"
    path.write_text(
        "target: .\n"
        "fail_on: high\n"
        "tools:\n"
        "  rytscan:\n"
        "    enabled: true\n"
        "    path: ./\n"
        "  schemalock:\n"
        "    enabled: false\n"
        "  vaultsweep:\n"
        "    enabled: false\n"
        "  shieldscan:\n"
        "    enabled: false\n"
    )
    return str(path)


def test_validate_config_valid_returns_zero_and_reports_enabled(good_config, capsys):
    assert main(["validate-config", "--config", good_config]) == 0
    captured = capsys.readouterr()
    assert "enabled" in captured.out
    assert "disabled" in captured.out
    assert "rytscan" in captured.out


def test_validate_config_missing_config_returns_two(capsys):
    assert main(["validate-config", "--config", "/nonexistent.yaml"]) == 2
    captured = capsys.readouterr()
    assert "Config error" in captured.err


def test_validate_config_does_not_run_any_scan(good_config, monkeypatch):
    with monkeypatch.context() as m:
        m.setattr("stellargate.cli.run_all", lambda cfg: (_ for _ in ()).throw(AssertionError("must not run")))
        assert main(["validate-config", "--config", good_config]) == 0
