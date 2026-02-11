"""Tests for the Mach-O LC_LOAD_DYLIB injector."""

import struct

from flow_patcher.inject import (
    FAT_MAGIC,
    _inject_slice,
    inject_dylib,
)
from tests.conftest import build_macho_header

DYLIB_PATH = "@executable_path/../Frameworks/FlowPatch.dylib"

# ── Helpers ──────────────────────────────────────────────────────────────────


def _build_fat_binary(slices: list[bytearray]) -> bytearray:
    """Wrap multiple Mach-O slices into a FAT binary."""
    # FAT header: magic(4) + nfat(4) + nfat * fat_arch(20)
    header_size = 8 + len(slices) * 20
    # Align each slice to 0x1000
    align_bits = 12  # 2^12 = 4096

    buf = bytearray()
    buf += struct.pack(">I", FAT_MAGIC)
    buf += struct.pack(">I", len(slices))

    offset = header_size
    for _, s in enumerate(slices):
        # Align offset
        offset = (offset + 0xFFF) & ~0xFFF
        cputype = struct.unpack_from("<I", s, 4)[0]
        buf += struct.pack(">I", cputype)  # cputype
        buf += struct.pack(">I", 0)  # cpusubtype
        buf += struct.pack(">I", offset)  # offset
        buf += struct.pack(">I", len(s))  # size
        buf += struct.pack(">I", align_bits)  # align
        offset += len(s)

    # Pad + write slices
    for _, s in enumerate(slices):
        while len(buf) % 0x1000 != 0:
            buf += b"\x00"
        buf += s

    return buf


def _write_to_tmpfile(data: bytearray, tmp_path) -> str:
    """Write binary data to a temp file and return its path."""
    p = tmp_path / "test_binary"
    p.write_bytes(bytes(data))
    return str(p)


# ── inject_slice tests ───────────────────────────────────────────────────────


class TestInjectSlice:
    """Tests for _inject_slice on thin Mach-O binaries."""

    def test_basic_injection(self, tmp_path):
        """A single injection should succeed and update ncmds/sizeofcmds."""
        buf = build_macho_header(padding=256)
        path = _write_to_tmpfile(buf, tmp_path)

        with open(path, "r+b") as f:
            assert _inject_slice(f, 0, DYLIB_PATH) is True

        with open(path, "rb") as f:
            f.seek(16)
            ncmds, sizeofcmds = struct.unpack("<2I", f.read(8))
            assert ncmds == 2  # original 1 + injected
            assert sizeofcmds > 152  # original segment cmd size

    def test_duplicate_injection_skips(self, tmp_path):
        """Injecting the same dylib twice should skip the second time."""
        buf = build_macho_header(padding=256)
        path = _write_to_tmpfile(buf, tmp_path)

        with open(path, "r+b") as f:
            assert _inject_slice(f, 0, DYLIB_PATH) is True
        with open(path, "r+b") as f:
            assert _inject_slice(f, 0, DYLIB_PATH) is True  # skip

        # ncmds should still be 2, not 3
        with open(path, "rb") as f:
            f.seek(16)
            ncmds = struct.unpack("<I", f.read(4))[0]
            assert ncmds == 2

    def test_updates_header_counts(self, tmp_path):
        """After injection, ncmds and sizeofcmds should be correctly incremented."""
        buf = build_macho_header(padding=256)
        path = _write_to_tmpfile(buf, tmp_path)

        # Read original values
        with open(path, "rb") as f:
            f.seek(16)
            orig_ncmds, orig_sizeofcmds = struct.unpack("<2I", f.read(8))

        with open(path, "r+b") as f:
            _inject_slice(f, 0, DYLIB_PATH)

        with open(path, "rb") as f:
            f.seek(16)
            new_ncmds, new_sizeofcmds = struct.unpack("<2I", f.read(8))

        assert new_ncmds == orig_ncmds + 1
        assert new_sizeofcmds > orig_sizeofcmds

    def test_wrong_magic_fails(self, tmp_path):
        """Non-Mach-O data should fail gracefully."""
        buf = bytearray(b"\x00" * 256)
        path = _write_to_tmpfile(buf, tmp_path)

        with open(path, "r+b") as f:
            assert _inject_slice(f, 0, DYLIB_PATH) is False

    def test_injected_dylib_name_readable(self, tmp_path):
        """The injected LC_LOAD_DYLIB should contain the correct dylib path."""
        buf = build_macho_header(padding=256)
        path = _write_to_tmpfile(buf, tmp_path)

        with open(path, "r+b") as f:
            _inject_slice(f, 0, DYLIB_PATH)

        with open(path, "rb") as f:
            data = f.read()
            assert DYLIB_PATH.encode("utf-8") in data

    def test_x86_64_slice(self, tmp_path):
        """Injection should work for x86_64 slices too."""
        buf = build_macho_header(cputype=7, padding=256)  # x86_64
        path = _write_to_tmpfile(buf, tmp_path)

        with open(path, "r+b") as f:
            assert _inject_slice(f, 0, DYLIB_PATH) is True


# ── inject_dylib tests ───────────────────────────────────────────────────────


class TestInjectDylib:
    """Tests for inject_dylib (FAT + thin entry point)."""

    def test_thin_binary(self, tmp_path):
        """inject_dylib should work on a thin (non-FAT) binary."""
        buf = build_macho_header(padding=256)
        path = _write_to_tmpfile(buf, tmp_path)
        assert inject_dylib(path, DYLIB_PATH) is True

    def test_fat_binary(self, tmp_path):
        """inject_dylib should inject into all slices of a FAT binary."""
        arm = build_macho_header(cputype=0x100000C, padding=256)
        x86 = build_macho_header(cputype=7, padding=256)
        fat = _build_fat_binary([arm, x86])
        path = _write_to_tmpfile(fat, tmp_path)
        assert inject_dylib(path, DYLIB_PATH) is True

    def test_unknown_format(self, tmp_path):
        """Unknown binary format should return False."""
        buf = bytearray(b"\xde\xad\xbe\xef" + b"\x00" * 252)
        path = _write_to_tmpfile(buf, tmp_path)
        assert inject_dylib(path, DYLIB_PATH) is False
