"""Tests for the CLI probe command."""

import argparse
import json
from pathlib import Path
from unittest import mock

import pytest

from flow_patcher.cli import cmd_probe
from flow_patcher.probe import ProbeResult


@pytest.fixture
def mock_probe_result():
    return ProbeResult(
        version="4.6.1",
        architectures=["arm64"],
        padding={"arm64": 100},
        classes={"RCEntitlementInfo": True, "FIRAnalytics": True},
        selectors={"isActive": True},
        verdict=True,
        details=[],
    )


@pytest.fixture
def mock_args(tmp_path):
    args = mock.Mock(spec=argparse.Namespace)
    args.app_path = str(tmp_path / "Flow.app")
    args.json = False
    args.save = False
    args.baseline = None
    return args


def test_probe_app_not_found(mock_args, capsys):
    """Test that file not found error is raised."""
    # Ensure app does not exist
    with pytest.raises(FileNotFoundError):
        cmd_probe(mock_args)


def test_probe_json_output(mock_args, mock_probe_result, monkeypatch, capsys):
    """Test JSON output format."""
    Path(mock_args.app_path).touch()  # Mock existence check
    mock_args.json = True

    monkeypatch.setattr("flow_patcher.cli.probe_app", lambda x: mock_probe_result)

    cmd_probe(mock_args)

    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert output["version"] == "4.6.1"
    assert output["verdict"] is True


def test_probe_human_output_compatible(mock_args, mock_probe_result, monkeypatch, capsys):
    """Test human readable output for compatible app."""
    Path(mock_args.app_path).touch()

    monkeypatch.setattr("flow_patcher.cli.probe_app", lambda x: mock_probe_result)

    cmd_probe(mock_args)

    captured = capsys.readouterr()
    assert "Flow version:     4.6.1" in captured.out
    assert "Verdict:          COMPATIBLE" in captured.out
    assert "Classes found:" in captured.out
    # Check for class and status on the same line, ignoring exact whitespace
    assert "RCEntitlementInfo" in captured.out
    assert "OK" in captured.out
    assert any("RCEntitlementInfo" in line and "OK" in line for line in captured.out.splitlines())


def test_probe_human_output_incompatible(mock_args, mock_probe_result, monkeypatch, capsys):
    """Test human readable output for incompatible app."""
    Path(mock_args.app_path).touch()
    mock_probe_result.verdict = False
    mock_probe_result.details = ["Padding insufficient", "Missing classes: FIRAnalytics"]
    mock_probe_result.classes["FIRAnalytics"] = False

    monkeypatch.setattr("flow_patcher.cli.probe_app", lambda x: mock_probe_result)

    cmd_probe(mock_args)

    captured = capsys.readouterr()
    assert "Verdict:          INCOMPATIBLE" in captured.out
    assert "FIRAnalytics                        MISSING" in captured.out
    assert "Details:" in captured.out
    assert "- Padding insufficient" in captured.out
    assert "- Missing classes: FIRAnalytics" in captured.out


def test_probe_save_baseline(mock_args, mock_probe_result, monkeypatch, tmp_path, capsys):
    """Test saving compatibility.json."""
    Path(mock_args.app_path).touch()
    mock_args.save = True

    # Run in a temp dir to avoid writing to actual repo
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("flow_patcher.cli.probe_app", lambda x: mock_probe_result)

    cmd_probe(mock_args)

    baseline = tmp_path / "compatibility.json"
    assert baseline.exists()
    data = json.loads(baseline.read_text())
    assert data["version"] == "4.6.1"
    assert "Saving baseline" in capsys.readouterr().err


def test_probe_compare_baseline_no_changes(
    mock_args, mock_probe_result, monkeypatch, tmp_path, capsys
):
    """Test comparison with matching baseline."""
    Path(mock_args.app_path).touch()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("flow_patcher.cli.probe_app", lambda x: mock_probe_result)

    # Create matching baseline
    baseline = tmp_path / "compatibility.json"
    from dataclasses import asdict

    baseline.write_text(json.dumps(asdict(mock_probe_result)))
    mock_args.baseline = str(baseline)

    cmd_probe(mock_args)

    captured = capsys.readouterr()
    assert "(No changes detected)" in captured.out


def test_probe_compare_baseline_changes(
    mock_args, mock_probe_result, monkeypatch, tmp_path, capsys
):
    """Test comparison with differing baseline."""
    Path(mock_args.app_path).touch()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("flow_patcher.cli.probe_app", lambda x: mock_probe_result)

    # Create differing baseline (older version)
    baseline_data = {
        "version": "4.5.0",
        "architectures": ["arm64"],
        "padding": {"arm64": 100},
        "classes": {
            "RCEntitlementInfo": True,
            "OldClass": True,
        },  # OldClass removed in new
        "selectors": {"isActive": True},
    }
    baseline = tmp_path / "compatibility.json"
    baseline.write_text(json.dumps(baseline_data))
    mock_args.baseline = str(baseline)

    cmd_probe(mock_args)

    captured = capsys.readouterr()
    assert "Change from baseline:" in captured.out
    assert "Version: 4.5.0 -> 4.6.1" in captured.out
    assert "New checked class: FIRAnalytics" in captured.out
