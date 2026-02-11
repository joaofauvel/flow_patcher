"""Mach-O LC_LOAD_DYLIB injector for FAT and thin binaries."""

import struct
from io import BufferedRandom

FAT_MAGIC = 0xCAFEBABE
MH_MAGIC_64 = 0xFEEDFACF
LC_LOAD_DYLIB = 0xC
LC_SEGMENT_64 = 0x19


def _inject_slice(f: BufferedRandom, slice_offset: int, dylib_path: str) -> bool:
    """Add an LC_LOAD_DYLIB command to a single Mach-O 64-bit slice."""
    f.seek(slice_offset)
    # magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
    magic, cputype, _, _, ncmds, sizeofcmds, _, _ = struct.unpack("<8I", f.read(32))
    if magic != MH_MAGIC_64:
        return False

    arch = "arm64" if cputype == 0x100000C else "x86_64"
    header_size = 32
    cmds_end = slice_offset + header_size + sizeofcmds

    # Check for duplicate injection
    f.seek(slice_offset + header_size)
    for _ in range(ncmds):
        pos = f.tell()
        cmd, cmdsize = struct.unpack("<2I", f.read(8))
        if cmd == LC_LOAD_DYLIB:
            name_off = struct.unpack("<I", f.read(4))[0]
            f.seek(pos + name_off)
            raw = f.read(cmdsize - name_off)
            name = raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            if name == dylib_path:
                print(f"  [{arch}] Already injected, skipping.")
                return True
        f.seek(pos + cmdsize)

    # Find first section data offset (padding boundary)
    f.seek(slice_offset + header_size)
    first_data = None
    for _ in range(ncmds):
        pos = f.tell()
        cmd, cmdsize = struct.unpack("<2I", f.read(8))
        if cmd == LC_SEGMENT_64:
            f.read(16)  # segname
            # vmaddr, vmsize, fileoff, filesize
            _, _, _, _ = struct.unpack("<4Q", f.read(32))
            # maxprot, initprot, nsects, flags
            _, _, nsects, _ = struct.unpack("<4I", f.read(16))
            if nsects > 0:
                f.read(32)  # sectname + segname
                struct.unpack("<2Q", f.read(16))  # addr, size
                sect_offset = struct.unpack("<I", f.read(4))[0]
                if sect_offset > 0:
                    candidate = slice_offset + sect_offset
                    if first_data is None or candidate < first_data:
                        first_data = candidate
        f.seek(pos + cmdsize)

    if first_data is None:
        print(f"  [{arch}] Cannot determine padding limit")
        return False

    # Build new command
    name_bytes = dylib_path.encode("utf-8") + b"\x00"
    name_offset = 24
    padded = (len(name_bytes) + 3) & ~3
    new_cmdsize = name_offset + padded
    avail = first_data - cmds_end

    if avail < new_cmdsize:
        print(f"  [{arch}] Not enough header padding ({avail} < {new_cmdsize})")
        return False

    print(f"  [{arch}] Injecting at {cmds_end:#x} ({avail}b padding)")

    f.seek(cmds_end)
    f.write(struct.pack("<I", LC_LOAD_DYLIB))
    f.write(struct.pack("<I", new_cmdsize))
    f.write(struct.pack("<I", name_offset))
    f.write(struct.pack("<I", 0))  # timestamp
    f.write(struct.pack("<I", 0x10000))  # current_version
    f.write(struct.pack("<I", 0x10000))  # compat_version
    f.write(name_bytes.ljust(padded, b"\x00"))

    # Update header counts
    f.seek(slice_offset + 16)
    f.write(struct.pack("<I", ncmds + 1))
    f.write(struct.pack("<I", sizeofcmds + new_cmdsize))
    print(f"  [{arch}] Done.")
    return True


def inject_dylib(binary_path: str, dylib_install_path: str) -> bool:
    """Inject an LC_LOAD_DYLIB into all slices of a Mach-O binary."""
    with open(binary_path, "r+b") as f:
        # FAT headers are always big-endian; Mach-O headers are little-endian
        magic = struct.unpack(">I", f.read(4))[0]

        if magic == FAT_MAGIC:
            nfat = struct.unpack(">I", f.read(4))[0]
            slices = []
            for _ in range(nfat):
                _, _, off, _, _ = struct.unpack(">5I", f.read(20))
                slices.append(off)
            ok = True
            for off in slices:
                ok = _inject_slice(f, off, dylib_install_path) and ok
            return ok
        else:
            f.seek(0)
            m2 = struct.unpack("<I", f.read(4))[0]
            if m2 == MH_MAGIC_64:
                return _inject_slice(f, 0, dylib_install_path)
            else:
                print(f"Unknown binary format: {magic:#x}")
                return False
