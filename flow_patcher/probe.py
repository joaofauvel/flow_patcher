"""Non-destructive inspection of Flow.app binaries for compatibility checking."""

import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from flow_patcher.inject import FAT_MAGIC, LC_SEGMENT_64, MH_MAGIC_64

# Minimum padding required for LC_LOAD_DYLIB injection
REQUIRED_PADDING = 80

# Critical classes - Patch WILL fail if missing
CRITICAL_CLASSES = [
    "RCEntitlementInfo",
    "NSPersistentContainer",
]

# Optional classes - Patch works (hooks skipped) if missing
OPTIONAL_CLASSES = [
    "FIRAnalytics",
    "FIRAnalyticsConfiguration",
    "FIRHeartbeatLogger",
    "GDTCORTransport",
]

# Critical selectors
CRITICAL_SELECTORS = [
    "isActive",
    "loadPersistentStoresWithCompletionHandler:",
]

# Optional selectors
OPTIONAL_SELECTORS = [
    "logEventWithName:parameters:",
]

ALL_CLASSES = CRITICAL_CLASSES + OPTIONAL_CLASSES
ALL_SELECTORS = CRITICAL_SELECTORS + OPTIONAL_SELECTORS


@dataclass
class ProbeResult:
    version: str
    architectures: list[str]
    padding: dict[str, int]  # arch -> bytes
    classes: dict[str, bool]
    selectors: dict[str, bool]
    verdict: bool = False
    details: list[str] = field(default_factory=list)


def get_flow_version(app_path: Path) -> str:
    """Read CFBundleShortVersionString from Info.plist."""
    plist = app_path / "Contents" / "Info.plist"
    if not plist.exists():
        return "Unknown"

    try:
        res = subprocess.run(
            ["defaults", "read", str(plist), "CFBundleShortVersionString"],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except FileNotFoundError:
        pass

    return "Unknown"


def _check_slice_padding(f: Any, slice_offset: int) -> int:
    """Calculate available padding in a Mach-O slice. Returns bytes or -1 on error."""
    f.seek(slice_offset)
    try:
        header = f.read(32)
        if len(header) < 32:
            return -1
        magic, _, _, _, _, sizeofcmds, _, _ = struct.unpack("<8I", header)
    except struct.error:
        return -1

    if magic != MH_MAGIC_64:
        return -1

    header_size = 32
    cmds_end = slice_offset + header_size + sizeofcmds

    f.seek(slice_offset + header_size)
    first_data = None

    current_cmds_size = 0
    while current_cmds_size < sizeofcmds:
        pos = f.tell()
        try:
            cmd_header = f.read(8)
            if len(cmd_header) < 8:
                break
            cmd, cmdsize = struct.unpack("<2I", cmd_header)
        except struct.error:
            break

        if cmd == LC_SEGMENT_64:
            f.read(16)  # segname
            # vmaddr, vmsize, fileoff, filesize
            _, _, _, _ = struct.unpack("<4Q", f.read(32))
            # maxprot, initprot, nsects, flags
            _, _, nsects, _ = struct.unpack("<4I", f.read(16))

            if nsects > 0:
                for _ in range(nsects):
                    sect_header = f.read(80)
                    if len(sect_header) < 80:
                        break
                    # offset is at 48
                    sect_offset = int(struct.unpack("<I", sect_header[48:52])[0])
                    if sect_offset > 0:
                        candidate = slice_offset + sect_offset
                        if first_data is None or candidate < first_data:
                            first_data = candidate

        f.seek(pos + cmdsize)
        current_cmds_size += cmdsize

    if first_data is None:
        return -1

    return int(first_data - cmds_end)


def check_padding(binary_path: Path) -> dict[str, int]:
    """Check Mach-O header padding for injection."""
    results = {}

    try:
        with open(binary_path, "rb") as f:
            header = f.read(4)
            if len(header) < 4:
                return {}

            magic = struct.unpack(">I", header)[0]

            if magic == FAT_MAGIC:
                nfat = struct.unpack(">I", f.read(4))[0]
                slices = []
                for _ in range(nfat):
                    # cputype, cpusubtype, offset, size, align
                    cputype, _, offset, _, _ = struct.unpack(">5I", f.read(20))
                    arch = "arm64" if cputype == 0x100000C else "x86_64"
                    slices.append((arch, offset))

                for arch, offset in slices:
                    padding = _check_slice_padding(f, offset)
                    results[arch] = padding

            elif magic == MH_MAGIC_64:
                # Need to re-read as LE to confirm or parse cputype
                f.seek(0)
                magic_le = struct.unpack("<I", f.read(4))[0]
                if magic_le == MH_MAGIC_64:
                    cputype = struct.unpack("<I", f.read(4))[0]
                    arch = "arm64" if cputype == 0x100000C else "x86_64"
                    padding = _check_slice_padding(f, 0)
                    results[arch] = padding
            elif magic == 0xCFFAEDFE:  # MH_MAGIC_64 LE read as BE
                # It's a thin binary
                f.seek(0)
                f.read(4)  # magic
                cputype = struct.unpack("<I", f.read(4))[0]
                arch = "arm64" if cputype == 0x100000C else "x86_64"
                padding = _check_slice_padding(f, 0)
                results[arch] = padding

    except Exception:
        pass

    return results


def check_symbols(binary_path: Path) -> tuple[dict[str, bool], dict[str, bool]]:
    """Check for existence of required classes and selectors using nm."""
    classes_found = {c: False for c in ALL_CLASSES}
    selectors_found = {s: False for s in ALL_SELECTORS}

    if not shutil.which("nm"):
        return classes_found, selectors_found

    try:
        res = subprocess.run(
            ["nm", "-a", str(binary_path)],
            capture_output=True,
            text=True,
            check=False,
            encoding="utf-8",
            errors="ignore",
        )
        if res.returncode != 0:
            return classes_found, selectors_found

        output = res.stdout

        for cls in ALL_CLASSES:
            if (
                f"_OBJC_CLASS_$___{cls}" in output
                or f"_OBJC_CLASS_$_{cls}" in output
                or f"class {cls}" in output
            ):
                classes_found[cls] = True

    except Exception:
        pass

    try:
        res = subprocess.run(
            ["strings", str(binary_path)],
            capture_output=True,
            text=True,
            check=False,
            encoding="utf-8",
            errors="ignore",
        )
        if res.returncode == 0:
            output = res.stdout
            for sel in ALL_SELECTORS:
                if sel in output:
                    selectors_found[sel] = True

            for cls in ALL_CLASSES:
                if not classes_found[cls] and cls in output:
                    classes_found[cls] = True
    except Exception:
        pass

    return classes_found, selectors_found


def probe_app(app_path: Path) -> ProbeResult:
    """Run all inspections on the app."""
    from flow_patcher.cli import _find_binary

    try:
        binary = _find_binary(app_path)
    except Exception as e:
        return ProbeResult(
            version="Error",
            architectures=[],
            padding={},
            classes={},
            selectors={},
            verdict=False,
            details=[f"Could not find binary: {e}"],
        )

    version = get_flow_version(app_path)
    padding = check_padding(binary)
    classes, selectors = check_symbols(binary)

    architectures = list(padding.keys())
    verdict = True
    details = []

    for arch, pad in padding.items():
        if pad < REQUIRED_PADDING:
            verdict = False
            details.append(f"Padding insufficient for {arch} ({pad} < {REQUIRED_PADDING})")

    # Critical failures
    missing_critical_classes = [c for c in CRITICAL_CLASSES if not classes[c]]
    if missing_critical_classes:
        verdict = False
        details.append(f"Missing CRITICAL classes: {', '.join(missing_critical_classes)}")

    missing_critical_selectors = [s for s in CRITICAL_SELECTORS if not selectors[s]]
    if missing_critical_selectors:
        verdict = False
        details.append(f"Missing CRITICAL selectors: {', '.join(missing_critical_selectors)}")

    # Optional / warnings
    missing_optional_classes = [c for c in OPTIONAL_CLASSES if not classes[c]]
    if missing_optional_classes:
        details.append(f"Missing optional classes (hooks will skip): {', '.join(missing_optional_classes)}")

    missing_optional_selectors = [s for s in OPTIONAL_SELECTORS if not selectors[s]]
    if missing_optional_selectors:
        details.append(f"Missing optional selectors (hooks will skip): {', '.join(missing_optional_selectors)}")

    return ProbeResult(
        version=version,
        architectures=architectures,
        padding=padding,
        classes=classes,
        selectors=selectors,
        verdict=verdict,
        details=details,
    )
