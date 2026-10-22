"""Exercise the published editor schema against real config loading."""
import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from stellargate.config import Config, KNOWN_TOOLS, VALID_SEVERITIES

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "stellargate.schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)


def test_schema_is_valid_and_tracks_loader_tools():
    Draft202012Validator.check_schema(SCHEMA)
    assert set(SCHEMA["properties"]["tools"]["properties"]) == set(KNOWN_TOOLS)


def test_published_example_validates_and_loads():
    path = ROOT / "stellargate.example.yaml"
    VALIDATOR.validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    loaded = Config.load(path)
    assert loaded.tools["rytscan"].enabled
    assert loaded.tools["schemalock"].options["config"] == "./schemalock.yaml"


@pytest.mark.parametrize("severity", [s for value in VALID_SEVERITIES for s in (value, value.upper(), value.title())])
def test_severities_match_case_insensitive_loader(severity, tmp_path):
    document = {"fail_on": severity, "tools": {"rytscan": {"enabled": True}}}
    VALIDATOR.validate(document)
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    assert Config.load(path).fail_on == severity.lower()


def test_optional_and_extensible_options_load_without_changes(tmp_path):
    document = {
        "custom_metadata": "allowed by loader",
        "tools": {
            "rytscan": {"enabled": True, "path": "contracts", "cache_file": "cache.json", "future_option": 1},
            "schemalock": {"enabled": True, "config": "api.yaml", "base_url": "http://127.0.0.1:8000"},
            "vaultsweep": {"enabled": True, "path": ".", "ignore_paths": ["tests/**", "*.example"]},
            "shieldscan": None,
        },
    }
    VALIDATOR.validate(document)
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    loaded = Config.load(path)
    assert loaded.tools["rytscan"].options["cache_file"] == "cache.json"
    assert loaded.tools["rytscan"].options["future_option"] == 1
    assert loaded.tools["vaultsweep"].options["ignore_paths"] == ["tests/**", "*.example"]
    assert not loaded.tools["shieldscan"].enabled


@pytest.mark.parametrize("document", [
    {},
    {"tools": {}},
    {"tools": {"rytscan": {}}},
    {"tools": {"rytscan": None}},
    {"tools": {"rytscan": {"enabled": False}}},
    {"tools": {"rytscann": {"enabled": True}}},
    {"tools": {"rytscan": {"enabled": "false"}}},
    {"tools": {"rytscan": {"enabled": 1}}},
    {"tools": {"vaultsweep": {"enabled": True, "ignore_paths": "tests/**"}}},
    {"tools": {"vaultsweep": {"enabled": True, "ignore_paths": [1]}}},
    {"tools": {"schemalock": {"enabled": True, "config": 42}}},
    {"tools": {"rytscan": {"enabled": True}}, "fail_on": "highest"},
    {"tools": {"rytscan": {"enabled": True}}, "target": 1},
])
def test_editor_rejects_invalid_shapes(document):
    assert not VALIDATOR.is_valid(document)
