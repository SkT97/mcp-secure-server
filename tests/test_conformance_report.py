"""Exercise the safe subset of the pinned runner's output."""

import json

import pytest

from examples.conformance import read_results, verify_runner_source


def test_unpinned_source_is_rejected(tmp_path):
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="source fingerprint mismatch"):
        verify_runner_source(tmp_path)


def test_report_keeps_outcomes_and_discards_free_text(tmp_path):
    entries = {
        "tools-list": [("wire-schema-valid", "SUCCESS")],
        "resources-list": [("resource-available", "FAILURE"), ("extra-info", "SKIPPED")],
        "tasks-list": [("tasks-check", "SKIPPED")],
    }
    for scenario, checks in entries.items():
        directory = tmp_path / f"server-{scenario}-2026-11-18T10-00-00-000Z"
        directory.mkdir()
        (directory / "checks.json").write_text(
            json.dumps(
                [
                    {"id": identifier, "status": status, "description": "discard this field"}
                    for identifier, status in checks
                ]
            ),
            encoding="utf-8",
        )
    expected = {
        "tools-list": True,
        "resources-list": True,
        "tasks-list": False,
        "prompts-list": True,
    }
    results = read_results(tmp_path, expected)
    assert [row["status"] for row in results] == ["passed", "failed", "skipped", "no_result"]
    assert [row["required"] for row in results] == [True, True, False, True]
    assert results[1]["checks"][1] == {"id": "extra-info", "status": "SKIPPED"}
    assert "discard this field" not in json.dumps(results)
