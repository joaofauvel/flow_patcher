"""Tests for the probe command logic."""

from unittest import mock

from flow_patcher.probe import (
    ALL_CLASSES,
    ALL_SELECTORS,
    CRITICAL_CLASSES,
    CRITICAL_SELECTORS,
    OPTIONAL_CLASSES,
    check_padding,
    check_symbols,
    get_flow_version,
    probe_app,
)
from tests.conftest import build_macho_header, create_fat_binary


class TestGetFlowVersion:
    def test_reads_plist(self, tmp_path, monkeypatch):
        app = tmp_path / "Flow.app"
        (app / "Contents").mkdir(parents=True)
        plist = app / "Contents" / "Info.plist"
        plist.touch()

        def fake_run(cmd, **kw):
            return mock.Mock(returncode=0, stdout="4.6.1\n")

        monkeypatch.setattr("subprocess.run", fake_run)
        assert get_flow_version(app) == "4.6.1"

    def test_returns_unknown_on_error(self, tmp_path, monkeypatch):
        app = tmp_path / "Flow.app"

        def fake_run(cmd, **kw):
            return mock.Mock(returncode=1)

        monkeypatch.setattr("subprocess.run", fake_run)
        assert get_flow_version(app) == "Unknown"


class TestCheckPadding:
    def test_thin_binary_ok(self, tmp_path):
        bin_path = tmp_path / "Flow"
        data = build_macho_header(padding=100)
        bin_path.write_bytes(data)

        results = check_padding(bin_path)
        assert results == {"arm64": 100}

    def test_thin_binary_insufficient(self, tmp_path):
        bin_path = tmp_path / "Flow"
        data = build_macho_header(padding=40)
        bin_path.write_bytes(data)

        results = check_padding(bin_path)
        assert results == {"arm64": 40}

    def test_fat_binary(self, tmp_path):
        bin_path = tmp_path / "Flow"
        # Create FAT binary manually or reuse logic
        # Ideally import _create_fat_binary logic locally as helper
        create_fat_binary(bin_path, [("arm64", 200), ("x86_64", 40)])

        results = check_padding(bin_path)
        assert results["arm64"] == 200
        assert results["x86_64"] == 40


class TestCheckSymbols:
    def test_nm_finds_classes(self, tmp_path, monkeypatch):
        bin_path = tmp_path / "Flow"
        bin_path.touch()

        def fake_run(cmd, **kw):
            if cmd[0] == "nm":
                # Returns RCEntitlementInfo but missing FIRAnalytics
                return mock.Mock(returncode=0, stdout="_OBJC_CLASS_$_RCEntitlementInfo\n")
            elif cmd[0] == "strings":
                # Fallback
                return mock.Mock(returncode=0, stdout="")
            return mock.Mock(returncode=1)

        monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/nm")
        monkeypatch.setattr("subprocess.run", fake_run)

        classes, _ = check_symbols(bin_path)
        assert classes["RCEntitlementInfo"] is True
        # FIRAnalytics is in OPTIONAL_CLASSES
        if "FIRAnalytics" in classes:
            assert classes["FIRAnalytics"] is False

    def test_strings_finds_selectors(self, tmp_path, monkeypatch):
        bin_path = tmp_path / "Flow"
        bin_path.touch()

        def fake_run(cmd, **kw):
            if cmd[0] == "nm":
                return mock.Mock(returncode=0, stdout="")  # nm finds nothing
            if cmd[0] == "strings":
                return mock.Mock(returncode=0, stdout="isActive\nlogEventWithName:parameters:\n")
            return mock.Mock(returncode=1)

        monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/nm")
        monkeypatch.setattr("subprocess.run", fake_run)

        _, selectors = check_symbols(bin_path)
        assert selectors["isActive"] is True
        assert selectors["logEventWithName:parameters:"] is True


class TestProbeApp:
    def test_verdict_pass(self, tmp_path, monkeypatch):
        app = tmp_path / "Flow.app"
        binary = app / "Contents" / "MacOS" / "Flow"
        binary.parent.mkdir(parents=True)
        binary.touch()

        # Mock parts
        monkeypatch.setattr("flow_patcher.probe.get_flow_version", lambda x: "4.6.1")
        monkeypatch.setattr("flow_patcher.cli._find_binary", lambda x: binary)
        monkeypatch.setattr("flow_patcher.probe.check_padding", lambda x: {"arm64": 100})
        monkeypatch.setattr(
            "flow_patcher.probe.check_symbols",
            lambda x: ({c: True for c in ALL_CLASSES}, {s: True for s in ALL_SELECTORS}),
        )

        result = probe_app(app)
        assert result.verdict is True
        assert not result.details

    def test_verdict_fail_padding(self, tmp_path, monkeypatch):
        app = tmp_path / "Flow.app"
        binary = app / "Contents" / "MacOS" / "Flow"

        monkeypatch.setattr("flow_patcher.probe.get_flow_version", lambda x: "4.6.1")
        monkeypatch.setattr("flow_patcher.cli._find_binary", lambda x: binary)
        monkeypatch.setattr("flow_patcher.probe.check_padding", lambda x: {"arm64": 40})  # Fail
        monkeypatch.setattr(
            "flow_patcher.probe.check_symbols",
            lambda x: ({c: True for c in ALL_CLASSES}, {s: True for s in ALL_SELECTORS}),
        )

        result = probe_app(app)
        assert result.verdict is False
        assert any("padding" in d.lower() for d in result.details)

    def test_verdict_missing_critical_class(self, tmp_path, monkeypatch):
        app = tmp_path / "Flow.app"
        binary = app / "Contents" / "MacOS" / "Flow"

        monkeypatch.setattr("flow_patcher.probe.get_flow_version", lambda x: "4.6.1")
        monkeypatch.setattr("flow_patcher.cli._find_binary", lambda x: binary)
        monkeypatch.setattr("flow_patcher.probe.check_padding", lambda x: {"arm64": 100})
        
        classes = {c: True for c in ALL_CLASSES}
        classes[CRITICAL_CLASSES[0]] = False

        monkeypatch.setattr(
            "flow_patcher.probe.check_symbols",
            lambda x: (classes, {s: True for s in ALL_SELECTORS}),
        )

        result = probe_app(app)
        assert result.verdict is False
        assert any("Missing CRITICAL classes" in d for d in result.details)

    def test_verdict_missing_optional_class(self, tmp_path, monkeypatch):
        app = tmp_path / "Flow.app"
        binary = app / "Contents" / "MacOS" / "Flow"

        monkeypatch.setattr("flow_patcher.probe.get_flow_version", lambda x: "4.6.1")
        monkeypatch.setattr("flow_patcher.cli._find_binary", lambda x: binary)
        monkeypatch.setattr("flow_patcher.probe.check_padding", lambda x: {"arm64": 100})
        
        classes = {c: True for c in ALL_CLASSES}
        if OPTIONAL_CLASSES:
            classes[OPTIONAL_CLASSES[0]] = False

        monkeypatch.setattr(
            "flow_patcher.probe.check_symbols",
            lambda x: (classes, {s: True for s in ALL_SELECTORS}),
        )

        result = probe_app(app)
        assert result.verdict is True  # Should pass
        if OPTIONAL_CLASSES:
            assert any("Missing optional classes" in d for d in result.details)
