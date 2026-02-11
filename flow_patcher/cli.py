"""CLI entry point for flow-patcher."""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from flow_patcher.inject import inject_dylib
from flow_patcher.probe import REQUIRED_PADDING, probe_app

DYLIB_NAME = "FlowPatch.dylib"
INSTALL_PATH = f"@executable_path/../Frameworks/{DYLIB_NAME}"
DYLIB_SRC = Path(__file__).parent / "patch_dylib.m"

BUNDLE_ID = "design.yugen.Flow"
CONTAINER = Path.home() / "Library" / "Containers" / BUNDLE_ID / "Data" / "Library"
GROUP_CONTAINER = Path.home() / "Library" / "Group Containers" / f"group.{BUNDLE_ID}" / "Library"

# Data to migrate from sandboxed container → non-sandboxed ~/Library
DATA_MIGRATIONS = [
    # (source relative to CONTAINER, dest relative to ~/Library)
    ("Application Support/Flow", "Application Support/Flow"),
    (f"Preferences/{BUNDLE_ID}.plist", f"Preferences/{BUNDLE_ID}.plist"),
]


def _find_binary(app_path: Path) -> Path:
    """Resolve the main executable inside a .app bundle."""
    macos_dir = app_path / "Contents" / "MacOS"
    if not macos_dir.is_dir():
        raise FileNotFoundError(f"{macos_dir} not found. Is this a valid .app bundle?")
    exe_name = app_path.stem
    exe = macos_dir / exe_name
    if not exe.is_file():
        candidates = [f for f in macos_dir.iterdir() if f.is_file() and os.access(f, os.X_OK)]
        if not candidates:
            raise FileNotFoundError(f"No executable found in {macos_dir}")
        exe = candidates[0]
    return exe


def _compile_dylib(output: Path) -> None:
    """Compile the ObjC swizzle dylib."""
    if not DYLIB_SRC.exists():
        raise FileNotFoundError(f"Dylib source not found at {DYLIB_SRC}")

    if not shutil.which("clang"):
        raise RuntimeError(
            "clang not found. Install Xcode Command Line Tools: xcode-select --install"
        )

    print(f"[*] Compiling patch dylib from {DYLIB_SRC}...")
    try:
        subprocess.run(
            [
                "clang",
                "-dynamiclib",
                "-framework",
                "Foundation",
                "-framework",
                "CoreData",
                "-arch",
                "arm64",
                "-arch",
                "x86_64",
                "-o",
                str(output),
                str(DYLIB_SRC),
                "-install_name",
                INSTALL_PATH,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        sys.exit(f"Compilation failed:\n{e.stderr}")


def _migrate_data() -> None:
    """Copy user data from the sandboxed container to non-sandboxed ~/Library."""
    home_lib = Path.home() / "Library"

    for src_rel, dst_rel in DATA_MIGRATIONS:
        src = CONTAINER / src_rel
        dst = home_lib / dst_rel

        if not src.exists():
            continue

        if dst.exists():
            print(f"  [skip] {dst_rel} (already exists)")
            continue

        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(str(src), str(dst))
        else:
            shutil.copy2(str(src), str(dst))
        print(f"  [copy] {dst_rel}")


def cmd_patch(args: argparse.Namespace) -> None:
    """Patch the app: copy to ~/Applications, inject dylib, migrate data."""
    source = Path(args.app_path).resolve()
    if not source.is_dir() or not source.name.endswith(".app"):
        raise ValueError(f"{source} is not a .app bundle.")

    dest_dir = Path.home() / "Applications"
    dest = dest_dir / source.name

    # Copy to ~/Applications
    dest_dir.mkdir(exist_ok=True)
    if dest.exists():
        print(f"[*] Removing old {dest}...")
        shutil.rmtree(str(dest))
    print(f"[*] Copying {source.name} to ~/Applications/...")
    shutil.copytree(str(source), str(dest), symlinks=True)

    # Clear xattrs
    subprocess.run(["xattr", "-cr", str(dest)], check=False)

    binary = _find_binary(dest)
    frameworks_dir = dest / "Contents" / "Frameworks"

    # Compile dylib into a temp file, then move to Frameworks/
    with tempfile.NamedTemporaryFile(suffix=".dylib", delete=False) as tmp:
        dylib_tmp = Path(tmp.name)
    try:
        _compile_dylib(dylib_tmp)
        frameworks_dir.mkdir(parents=True, exist_ok=True)
        print(f"[*] Installing {DYLIB_NAME} into Frameworks/...")
        shutil.copy2(dylib_tmp, frameworks_dir / DYLIB_NAME)
    finally:
        dylib_tmp.unlink(missing_ok=True)

    # Inject LC_LOAD_DYLIB
    print("[*] Injecting load command...")
    if not inject_dylib(str(binary), INSTALL_PATH):
        raise RuntimeError("Dylib injection failed.")

    # Ad-hoc re-sign (no entitlements — developer ents cause AMFI rejection)
    print("[*] Re-signing (ad-hoc)...")
    subprocess.run(
        ["codesign", "--force", "--deep", "--sign", "-", str(dest)],
        check=True,
    )

    # Migrate user data
    print("[*] Migrating user data from sandboxed container...")
    _migrate_data()

    print(f"[+] Done! Installed at ~/Applications/{source.name}")
    print(f"    Launch via Spotlight or: open ~/Applications/{source.name}")


def cmd_restore(args: argparse.Namespace) -> None:
    """Remove the patched copy from ~/Applications."""
    app_name = Path(args.app_path).name
    if not app_name.endswith(".app"):
        app_name = app_name + ".app"
    dest = Path.home() / "Applications" / app_name

    if not dest.is_dir():
        raise FileNotFoundError(f"No patched copy found at {dest}")

    shutil.rmtree(str(dest))
    print(f"[+] Removed {dest}")


def cmd_probe(args: argparse.Namespace) -> None:
    """Check app compatibility without modifying it."""
    try:
        import json
        from dataclasses import asdict
    except ImportError:
        pass  # Standard library

    app_path = Path(args.app_path).resolve()
    if not app_path.exists():
        raise FileNotFoundError(f"{app_path} not found")

    print(f"[*] Probing {app_path}...", file=sys.stderr)
    result = probe_app(app_path)

    # Resolve baseline path
    if args.save:
        if args.baseline:
            baseline_file = Path(args.baseline).resolve()
        else:
            baseline_file = Path("compatibility.json").resolve()
    else:
        # For reading, prefer args > package > local
        if args.baseline:
            baseline_file = Path(args.baseline).resolve()
        else:
            pkg_baseline = Path(__file__).parent.parent / "compatibility.json"
            if pkg_baseline.exists():
                baseline_file = pkg_baseline
            else:
                baseline_file = Path("compatibility.json").resolve()

    baseline = None
    if not args.save and baseline_file.exists():
        try:
            baseline = json.loads(baseline_file.read_text())
        except Exception:
            print("[!] Warning: Could not read existing compatibility.json", file=sys.stderr)

    if args.save:
        print(f"[*] Saving baseline to {baseline_file}...", file=sys.stderr)
        baseline_file.write_text(json.dumps(asdict(result), indent=2) + "\n")

    if args.json:
        print(json.dumps(asdict(result), indent=2))
        return

    # Human readable output
    print(f"Flow version:     {result.version}")
    architectures = ", ".join(result.architectures) if result.architectures else "None detected"
    print(f"Architectures:    {architectures}")

    for arch, pad in result.padding.items():
        status = "OK" if pad >= REQUIRED_PADDING else f"FAIL ({pad} < {REQUIRED_PADDING})"
        print(f"Header padding:   {arch}={pad}b (need {REQUIRED_PADDING}b) {status}")

    # Classes
    print("Classes found:")
    for cls, found in result.classes.items():
        status = "OK" if found else "MISSING"
        print(f"  {cls:<35} {status}")

    # Selectors
    print("Selectors found:")
    for sel, found in result.selectors.items():
        status = "OK" if found else "MISSING"
        print(f"  {sel:<45} {status}")

    verdict_str = "COMPATIBLE" if result.verdict else "INCOMPATIBLE"
    print(f"Verdict:          {verdict_str}")

    if result.details:
        print("\nDetails:")
        for detail in result.details:
            print(f"  - {detail}")

    # Baseline comparison
    if baseline and not args.save:
        print("\nChange from baseline:")
        current_dict = asdict(result)
        diffs = []
        if current_dict.get("version") != baseline.get("version"):
            diffs.append(f"Version: {baseline.get('version')} -> {current_dict.get('version')}")

        # Compare classes
        old_classes = baseline.get("classes", {})
        new_classes = current_dict.get("classes", {})
        for cls, found in new_classes.items():
            if cls not in old_classes:
                diffs.append(f"New checked class: {cls}")
            elif old_classes[cls] != found:
                status = "FOUND" if found else "LOST"
                diffs.append(f"Class {cls}: {status}")

        # Compare selectors
        old_sels = baseline.get("selectors", {})
        new_sels = current_dict.get("selectors", {})
        for sel, found in new_sels.items():
            if sel not in old_sels:
                diffs.append(f"New checked selector: {sel}")
            elif old_sels[sel] != found:
                status = "FOUND" if found else "LOST"
                diffs.append(f"Selector {sel}: {status}")

        if diffs:
            for d in diffs:
                print(f"  ! {d}")
        else:
            print("  (No changes detected)")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="flow-patcher",
        description="Permanently patch the Flow app to unlock Pro features.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_patch = sub.add_parser(
        "patch",
        help="Copy an app to ~/Applications, patch it, and migrate data",
    )
    p_patch.add_argument(
        "app_path",
        help="Path to the source .app bundle (e.g. /Applications/Flow.app)",
    )
    p_patch.set_defaults(func=cmd_patch)

    p_restore = sub.add_parser(
        "restore",
        help="Remove the patched copy from ~/Applications",
    )
    p_restore.add_argument(
        "app_path",
        help="App name or path (e.g. Flow.app)",
    )
    p_restore.set_defaults(func=cmd_restore)

    p_probe = sub.add_parser(
        "probe",
        help="Check app compatibility without modifying it",
    )
    p_probe.add_argument(
        "app_path",
        help="Path to the source .app bundle (e.g. /Applications/Flow.app)",
    )
    p_probe.add_argument(
        "--json",
        action="store_true",
        help="Output check results as JSON",
    )
    p_probe.add_argument(
        "--save",
        action="store_true",
        help="Save current probe result as baseline (compatibility.json)",
    )
    p_probe.add_argument(
        "--baseline",
        help="Path to compatibility baseline JSON (default: bundled or local compatibility.json)",
    )
    p_probe.set_defaults(func=cmd_probe)

    args = parser.parse_args()
    try:
        args.func(args)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        sys.exit(f"Error: {exc}")


if __name__ == "__main__":
    main()
