"""Shared test fixtures and helpers."""

import struct
from pathlib import Path

from flow_patcher.inject import FAT_MAGIC, LC_SEGMENT_64, MH_MAGIC_64


def create_fat_binary(path: Path, archs: list[tuple[str, int]]) -> None:
    """Create a FAT binary with the given architectures and padding."""
    # archs = [("arm64", 256), ("x86_64", 80)]
    nfat = len(archs)
    header = bytearray(8)
    struct.pack_into(">I", header, 0, FAT_MAGIC)
    struct.pack_into(">I", header, 4, nfat)

    offset = 4096  # Start slices at 4k
    slices_data = []

    # Fat arch headers
    fat_archs = bytearray()
    for arch, padding in archs:
        cputype = 0x100000C if arch == "arm64" else 0x1000007
        slice_data = build_macho_header(cputype=cputype, padding=padding)
        size = len(slice_data)

        # cputype, cpusubtype, offset, size, align
        fa = bytearray(20)
        struct.pack_into(">5I", fa, 0, cputype, 0, offset, size, 12)
        fat_archs += fa

        slices_data.append((offset, slice_data))
        offset += size
        offset = (offset + 4095) & ~4095  # Align next slice

    with open(path, "wb") as f:
        f.write(header)
        f.write(fat_archs)
        for off, data in slices_data:
            f.seek(off)
            f.write(data)


def build_macho_header(
    cputype: int = 0x100000C,
    ncmds: int = 1,
    padding: int = 256,
) -> bytearray:
    """Build a minimal 64-bit Mach-O binary with one __TEXT segment.

    Layout:
      [0..32)     Mach-O header (32 bytes)
      [32..H)     Load commands (one LC_SEGMENT_64 pointing to data)
      [H..H+pad)  Zero padding (where we inject LC_LOAD_DYLIB)
      [H+pad..)   Section data (just a sentinel byte)
    """
    # Segment command: LC_SEGMENT_64 with 1 section
    segname = b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    sectname = b"__text\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    seg_sectname = b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    # Section header: sectname(16) + segname(16) + addr(8) + size(8) +
    #                 offset(4) + align(4) + reloff(4) + nreloc(4) +
    #                 flags(4) + r1(4) + r2(4) + r3(4) = 80 bytes
    section_hdr = bytearray(80)
    section_hdr[0:16] = sectname
    section_hdr[16:32] = seg_sectname

    # Segment command header:
    # cmd(4) + cmdsize(4) + segname(16) + vmaddr(8) + vmsize(8) +
    # fileoff(8) + filesize(8) + maxprot(4) + initprot(4) + nsects(4) + flags(4)
    # = 72 bytes, plus 80 bytes per section = 152 total
    seg_cmdsize = 72 + 80
    seg_cmd = bytearray(72)
    struct.pack_into("<I", seg_cmd, 0, LC_SEGMENT_64)
    struct.pack_into("<I", seg_cmd, 4, seg_cmdsize)
    seg_cmd[8:24] = segname
    struct.pack_into("<Q", seg_cmd, 24, 0)  # vmaddr
    struct.pack_into("<Q", seg_cmd, 32, 0x1000)  # vmsize
    # maxprot=7, initprot=5, nsects=1, flags=0
    struct.pack_into("<I", seg_cmd, 56, 7)
    struct.pack_into("<I", seg_cmd, 60, 5)
    struct.pack_into("<I", seg_cmd, 64, 1)  # nsects
    struct.pack_into("<I", seg_cmd, 68, 0)

    sizeofcmds = seg_cmdsize
    header_end = 32 + sizeofcmds
    data_offset = header_end + padding

    # Fix segment fileoff/filesize
    struct.pack_into("<Q", seg_cmd, 40, data_offset)  # fileoff
    struct.pack_into("<Q", seg_cmd, 48, 16)  # filesize

    # Fix section offset
    struct.pack_into("<Q", section_hdr, 32, 0)  # addr
    struct.pack_into("<Q", section_hdr, 40, 16)  # size
    struct.pack_into("<I", section_hdr, 48, data_offset)  # offset

    # Mach-O header
    hdr = bytearray(32)
    struct.pack_into("<I", hdr, 0, MH_MAGIC_64)
    struct.pack_into("<I", hdr, 4, cputype)  # cputype
    struct.pack_into("<I", hdr, 8, 0)  # cpusubtype
    struct.pack_into("<I", hdr, 12, 2)  # filetype (MH_EXECUTE)
    struct.pack_into("<I", hdr, 16, ncmds)
    struct.pack_into("<I", hdr, 20, sizeofcmds)
    struct.pack_into("<I", hdr, 24, 0)  # flags
    struct.pack_into("<I", hdr, 28, 0)  # reserved

    buf = bytearray()
    buf += hdr
    buf += seg_cmd
    buf += section_hdr
    buf += b"\x00" * padding  # padding for injection
    buf += b"\xcc" * 16  # section data sentinel

    return buf
