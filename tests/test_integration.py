"""Integration tests running against the real Flow.app (if available)."""

import shutil
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from flow_patcher.cli import cmd_patch, cmd_probe


@pytest.mark.integration
def test_patch_and_probe_workflow(capsys, monkeypatch):
    """Full workflow: probe -> patch -> verify -> restore."""
    source_app = Path("/Applications/Flow.app")
    if not source_app.exists():
        pytest.skip("Flow.app not found in /Applications")

    # 1. Probe (non-destructive)
    print("\n[Integration] Probing...")
    args = mock.Mock()
    args.app_path = str(source_app)
    args.json = False
    args.save = False
    args.baseline = None

    cmd_probe(args)
    captured = capsys.readouterr()
    assert "Verdict:          COMPATIBLE" in captured.out, f"Probe failed:\n{captured.out}"

    # 2. Patch
    print("[Integration] Patching...")
    # Mock input/confirmation if any (currently patch implies 'yes')
    # Use a temporary home directory to avoid messing with real ~/Applications?
    # But we want to test real install path ~/Applications usually.
    # To be safe, let's use the real ~/Applications but ensure we clean up.

    dest_app = Path.home() / "Applications" / "Flow.app"
    if dest_app.exists():
        shutil.rmtree(dest_app)

    try:
        cmd_patch(args)

        assert dest_app.exists()
        assert (dest_app / "Contents" / "Frameworks" / "FlowPatch.dylib").exists()

        # Check if dylib is linked
        # We need to find the binary inside dest_app
        # We can reuse _find_binary logic or assume structure
        binary = dest_app / "Contents" / "MacOS" / source_app.stem
        # If binary name differs...
        if not binary.exists():
            # Try finding it
            candidates = list((dest_app / "Contents" / "MacOS").iterdir())
            binary = candidates[0]

        otool = subprocess.run(["otool", "-L", str(binary)], capture_output=True, text=True)
        assert "@executable_path/../Frameworks/FlowPatch.dylib" in otool.stdout

        print("[Integration] Patch Verified.")

    finally:
        # 3. Restore (Manual cleanup or use cmd_restore)
        if dest_app.exists():
            print("[Integration] Restoring...")
            shutil.rmtree(dest_app)
