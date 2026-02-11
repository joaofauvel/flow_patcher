"""Tests for the CLI commands (patch, restore, helpers)."""

import stat
from pathlib import Path
from unittest import mock

import pytest

from flow_patcher.cli import (
    BUNDLE_ID,
    DATA_MIGRATIONS,
    DYLIB_SRC,
    _compile_dylib,
    _find_binary,
    _migrate_data,
    cmd_patch,
    cmd_restore,
    main,
)
from tests.conftest import build_macho_header

# ── Helpers ──────────────────────────────────────────────────────────────────


def _create_fake_app(tmp_path: Path, name: str = "Flow.app") -> Path:
    """Create a minimal .app bundle with a fake executable."""
    app = tmp_path / name
    macos = app / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    exe = macos / name.removesuffix(".app")
    exe.write_bytes(bytes(build_macho_header()))
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    return app


# ── _find_binary tests ───────────────────────────────────────────────────────


class TestFindBinary:
    """Test executable resolution inside .app bundles."""

    def test_finds_named_binary(self, tmp_path):
        app = _create_fake_app(tmp_path)
        binary = _find_binary(app)
        assert binary.name == "Flow"
        assert binary.is_file()

    def test_finds_fallback_executable(self, tmp_path):
        """If the expected name doesn't match, pick the first executable."""
        app = tmp_path / "MyApp.app"
        macos = app / "Contents" / "MacOS"
        macos.mkdir(parents=True)
        exe = macos / "different_name"
        exe.write_bytes(b"\x00")
        exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
        binary = _find_binary(app)
        assert binary.name == "different_name"

    def test_exits_on_missing_macos_dir(self, tmp_path):
        app = tmp_path / "Bad.app"
        app.mkdir()
        with pytest.raises(FileNotFoundError):
            _find_binary(app)

    def test_exits_on_empty_macos_dir(self, tmp_path):
        app = tmp_path / "Empty.app"
        (app / "Contents" / "MacOS").mkdir(parents=True)
        with pytest.raises(FileNotFoundError):
            _find_binary(app)


# ── _migrate_data tests ─────────────────────────────────────────────────────


class TestMigrateData:
    """Test data migration from sandboxed to non-sandboxed paths."""

    def test_copies_missing_files(self, tmp_path, monkeypatch):
        """When dest doesn't exist, data should be copied."""
        container = tmp_path / "container"
        fake_home = tmp_path / "fakehome"

        plist_src = container / f"Preferences/{BUNDLE_ID}.plist"
        plist_src.parent.mkdir(parents=True)
        plist_src.write_text("fake plist")

        app_support_src = container / "Application Support/Flow"
        app_support_src.mkdir(parents=True)
        (app_support_src / "data.db").write_text("fake data")

        monkeypatch.setattr("flow_patcher.cli.CONTAINER", container)
        monkeypatch.setattr("pathlib.Path.home", staticmethod(lambda: fake_home))

        _migrate_data()

        assert (fake_home / "Library" / f"Preferences/{BUNDLE_ID}.plist").exists()
        assert (fake_home / "Library" / "Application Support/Flow/data.db").exists()

    def test_skips_existing_files(self, tmp_path, monkeypatch):
        """When dest already exists, it should not be overwritten."""
        container = tmp_path / "container"
        fake_home = tmp_path / "fakehome"

        plist_src = container / f"Preferences/{BUNDLE_ID}.plist"
        plist_src.parent.mkdir(parents=True)
        plist_src.write_text("new content")

        plist_dst = fake_home / "Library" / f"Preferences/{BUNDLE_ID}.plist"
        plist_dst.parent.mkdir(parents=True)
        plist_dst.write_text("old content")

        monkeypatch.setattr("flow_patcher.cli.CONTAINER", container)
        monkeypatch.setattr("pathlib.Path.home", staticmethod(lambda: fake_home))

        _migrate_data()

        assert plist_dst.read_text() == "old content"

    def test_missing_source_skipped(self, tmp_path, monkeypatch):
        """When source doesn't exist, migration should silently skip."""
        container = tmp_path / "empty_container"
        container.mkdir()
        fake_home = tmp_path / "fakehome"

        monkeypatch.setattr("flow_patcher.cli.CONTAINER", container)
        monkeypatch.setattr("pathlib.Path.home", staticmethod(lambda: fake_home))

        _migrate_data()  # should not raise


# ── cmd_restore tests ────────────────────────────────────────────────────────


class TestCmdRestore:
    """Test the restore command."""

    def test_removes_patched_app(self, tmp_path, monkeypatch):
        """Restore should delete the patched copy."""
        apps = tmp_path / "Applications"
        dest = apps / "Flow.app"
        dest.mkdir(parents=True)
        (dest / "sentinel").write_text("exists")

        monkeypatch.setattr("flow_patcher.cli.Path.home", lambda: tmp_path)

        args = mock.Mock()
        args.app_path = "/Applications/Flow.app"
        cmd_restore(args)

        assert not dest.exists()

    def test_exits_if_no_patched_copy(self, tmp_path, monkeypatch):
        """Restore should exit if there's nothing to remove."""
        apps = tmp_path / "Applications"
        apps.mkdir(parents=True)

        monkeypatch.setattr("flow_patcher.cli.Path.home", lambda: tmp_path)

        args = mock.Mock()
        args.app_path = "/Applications/Flow.app"
        with pytest.raises(FileNotFoundError):
            cmd_restore(args)

    def test_appends_dot_app_if_missing(self, tmp_path, monkeypatch):
        """Restore should handling names without .app suffix."""
        apps = tmp_path / "Applications"
        dest = apps / "Flow.app"
        dest.mkdir(parents=True)

        monkeypatch.setattr("flow_patcher.cli.Path.home", lambda: tmp_path)

        args = mock.Mock()
        args.app_path = "Flow"
        cmd_restore(args)

        assert not dest.exists()


# ── cmd_patch tests ──────────────────────────────────────────────────────────


class TestCompileDylib:
    """Test dylib compilation."""

    def test_calls_clang(self, tmp_path, monkeypatch):
        """_compile_dylib should invoke clang with the right flags."""
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)

        monkeypatch.setattr("subprocess.run", fake_run)
        _compile_dylib(tmp_path / "out.dylib")

        assert len(calls) == 1
        assert "clang" in calls[0][0]
        assert "-dynamiclib" in calls[0]
        assert "-framework" in calls[0]


class TestCmdPatch:
    """Test the patch command."""

    def test_rejects_non_app_path(self, tmp_path):
        """Patch should reject paths that aren't .app bundles."""
        notapp = tmp_path / "foo.txt"
        notapp.write_text("hello")
        args = mock.Mock()
        args.app_path = str(notapp)
        with pytest.raises(ValueError):
            cmd_patch(args)

    def test_rejects_nonexistent_path(self, tmp_path):
        """Patch should reject paths that don't exist."""
        args = mock.Mock()
        args.app_path = str(tmp_path / "NonExistent.app")
        with pytest.raises(ValueError):
            cmd_patch(args)

    def test_happy_path(self, tmp_path, monkeypatch):
        """Full patch flow with mocked subprocess calls."""
        app = _create_fake_app(tmp_path, "Flow.app")
        fake_home = tmp_path / "fakehome"
        fake_home.mkdir()

        monkeypatch.setattr("pathlib.Path.home", staticmethod(lambda: fake_home))
        monkeypatch.setattr("flow_patcher.cli.CONTAINER", tmp_path / "no_container")

        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            # Simulate clang producing a dylib file
            if cmd[0] == "clang":
                # Find -o flag
                for i, arg in enumerate(cmd):
                    if arg == "-o" and i + 1 < len(cmd):
                        Path(cmd[i + 1]).write_bytes(b"\x00" * 64)
                        break

        monkeypatch.setattr("subprocess.run", fake_run)

        args = mock.Mock()
        args.app_path = str(app)
        cmd_patch(args)

        dest = fake_home / "Applications" / "Flow.app"
        assert dest.is_dir()
        assert any("codesign" in c[0] for c in calls)


# ── main() tests ─────────────────────────────────────────────────────────────


class TestMain:
    """Test CLI argument parsing."""

    def test_no_args_exits(self):
        """Running with no arguments should print help and exit."""
        with pytest.raises(SystemExit), mock.patch("sys.argv", ["flow-patcher"]):
            main()

    def test_patch_subcommand_parsed(self, monkeypatch):
        """'patch' subcommand should dispatch to cmd_patch."""
        called = {}

        def fake_patch(args):
            called["args"] = args

        monkeypatch.setattr("flow_patcher.cli.cmd_patch", fake_patch)
        with mock.patch("sys.argv", ["flow-patcher", "patch", "/Foo.app"]):
            main()

        assert "args" in called
        assert called["args"].app_path == "/Foo.app"

    def test_restore_subcommand_parsed(self, monkeypatch):
        """'restore' subcommand should dispatch to cmd_restore."""
        called = {}

        def fake_restore(args):
            called["args"] = args

        monkeypatch.setattr("flow_patcher.cli.cmd_restore", fake_restore)
        with mock.patch("sys.argv", ["flow-patcher", "restore", "Flow.app"]):
            main()

        assert "args" in called
        assert called["args"].app_path == "Flow.app"


# ── Constants / config tests ────────────────────────────────────────────────


class TestConfig:
    """Smoke-test module-level constants."""

    def test_dylib_source_exists(self):
        assert DYLIB_SRC.exists(), f"patch_dylib.m not found at {DYLIB_SRC}"

    def test_bundle_id(self):
        assert BUNDLE_ID == "design.yugen.Flow"

    def test_data_migrations_not_empty(self):
        assert len(DATA_MIGRATIONS) >= 2
