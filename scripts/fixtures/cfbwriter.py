"""Minimal Compound File Binary (MS-CFB v3) writer for building test fixtures.

Streams smaller than 4096 bytes go into the mini stream. Each storage's children
form a right-sibling chain (a valid, if unbalanced, all-black red-black tree).
Also provides MS-OVBA compression helpers for vbaProject.bin fixtures.
"""
from __future__ import annotations

import struct

SECTOR = 512
MINI = 64
CUTOFF = 4096
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF


def clsid_bytes(s: str | None) -> bytes:
    if not s:
        return b"\0" * 16
    h = s.strip("{}").split("-")
    return struct.pack("<IHH", int(h[0], 16), int(h[1], 16), int(h[2], 16)) + bytes.fromhex(h[3] + h[4])


class Node:
    def __init__(self, name: str, data: bytes | None = None, clsid: str | None = None):
        self.name = name
        self.data = data
        self.clsid = clsid
        self.children: list[Node] = []
        self.sid = 0
        self.start = ENDOFCHAIN
        self.size = 0
        self._left = NOSTREAM
        self._right = NOSTREAM
        self._child = NOSTREAM

    def storage(self, name: str, clsid: str | None = None) -> "Node":
        n = Node(name, None, clsid)
        self.children.append(n)
        return n

    def stream(self, name: str, data: bytes) -> "Node":
        n = Node(name, bytes(data))
        self.children.append(n)
        return n


def _key(n: Node):
    return (len(n.name), n.name.upper())


def build(root_children_fn, root_clsid: str | None = None) -> bytes:
    root = Node("Root Entry", None, root_clsid)
    root_children_fn(root)
    entries = [root]

    def walk(n: Node):
        for c in sorted(n.children, key=_key):
            c.sid = len(entries)
            entries.append(c)
            walk(c)

    walk(root)

    fat: list[int] = []
    sectors: list[bytes] = []

    def alloc_chain(data: bytes) -> tuple[int, int]:
        if not data:
            return ENDOFCHAIN, 0
        parts = [data[i : i + SECTOR] for i in range(0, len(data), SECTOR)]
        start = len(sectors)
        for i, part in enumerate(parts):
            sid = len(sectors)
            sectors.append(part.ljust(SECTOR, b"\0"))
            fat.append(ENDOFCHAIN if i == len(parts) - 1 else sid + 1)
        return start, len(data)

    mini_buf = bytearray()
    mini_fat: list[int] = []

    def alloc_mini(data: bytes) -> tuple[int, int]:
        if not data:
            return ENDOFCHAIN, 0
        parts = [data[i : i + MINI] for i in range(0, len(data), MINI)]
        start = len(mini_buf) // MINI
        for i, part in enumerate(parts):
            mini_buf.extend(part.ljust(MINI, b"\0"))
            mini_fat.append(ENDOFCHAIN if i == len(parts) - 1 else start + i + 1)
        return start, len(data)

    for e in entries[1:]:
        if e.data is None:
            continue
        if len(e.data) >= CUTOFF:
            e.start, e.size = alloc_chain(e.data)
        else:
            e.start, e.size = alloc_mini(e.data)

    if mini_buf:
        root.start, root.size = alloc_chain(bytes(mini_buf))
    else:
        root.start, root.size = ENDOFCHAIN, 0

    first_mini_fat = ENDOFCHAIN
    mini_fat_count = 0
    if mini_fat:
        mf = b"".join(struct.pack("<I", x) for x in mini_fat)
        first_mini_fat, _ = alloc_chain(mf)
        mini_fat_count = (len(mf) + SECTOR - 1) // SECTOR

    for e in entries:
        e._left = e._right = e._child = NOSTREAM
    for e in entries:
        if e is not root and e.data is not None:
            continue
        kids = sorted(e.children, key=_key)
        if not kids:
            continue
        e._child = kids[0].sid
        for a, b in zip(kids, kids[1:] + [None]):
            a._left = NOSTREAM
            a._right = b.sid if b else NOSTREAM

    def pack_entry(e: Node) -> bytes:
        name = e.name.encode("utf-16le")[:62]
        typ = 5 if e is root else (1 if e.data is None else 2)
        return (
            name.ljust(64, b"\0")
            + struct.pack("<H", len(name) + 2 if e.name else 0)
            + bytes([typ, 0])
            + struct.pack("<III", e._left, e._right, e._child)
            + clsid_bytes(e.clsid)
            + struct.pack("<I", 0)
            + struct.pack("<Q", 0) * 2
            + struct.pack("<II", e.start, e.size & 0xFFFFFFFF)
            + struct.pack("<I", 0)
        )

    dir_bytes = b"".join(pack_entry(e) for e in entries)
    free = (
        b"\0" * 64
        + struct.pack("<H", 0)
        + bytes([0, 0])
        + struct.pack("<III", NOSTREAM, NOSTREAM, NOSTREAM)
        + b"\0" * 16
        + struct.pack("<I", 0)
        + struct.pack("<Q", 0) * 2
        + struct.pack("<II", ENDOFCHAIN, 0)
        + struct.pack("<I", 0)
    )
    while len(dir_bytes) % SECTOR:
        dir_bytes += free
    first_dir, _ = alloc_chain(dir_bytes)

    nfat = max(1, (len(sectors) + 127) // 128)
    while True:
        total = len(sectors) + nfat
        nfat2 = max(1, (total + 127) // 128)
        if nfat2 == nfat:
            break
        nfat = nfat2
    fat_start = len(sectors)
    while len(fat) < fat_start:
        fat.append(FREESECT)
    for i in range(nfat):
        if fat_start + i < len(fat):
            fat[fat_start + i] = FATSECT
        else:
            fat.append(FATSECT)
    while len(fat) < nfat * 128:
        fat.append(FREESECT)
    fat_bytes = b"".join(struct.pack("<I", x) for x in fat[: nfat * 128])
    for i in range(nfat):
        sectors.append(fat_bytes[i * SECTOR : (i + 1) * SECTOR])

    header = bytearray(SECTOR)
    header[0:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    header[0x18:0x1A] = struct.pack("<H", 0x003E)
    header[0x1A:0x1C] = struct.pack("<H", 3)
    header[0x1C:0x1E] = struct.pack("<H", 0xFFFE)
    header[0x1E:0x20] = struct.pack("<H", 9)
    header[0x20:0x22] = struct.pack("<H", 6)
    header[0x2C:0x30] = struct.pack("<I", nfat)
    header[0x30:0x34] = struct.pack("<I", first_dir)
    header[0x38:0x3C] = struct.pack("<I", CUTOFF)
    header[0x3C:0x40] = struct.pack("<I", first_mini_fat)
    header[0x40:0x44] = struct.pack("<I", mini_fat_count)
    header[0x44:0x48] = struct.pack("<I", ENDOFCHAIN)
    header[0x48:0x4C] = struct.pack("<I", 0)
    for i in range(109):
        header[0x4C + i * 4 : 0x4C + (i + 1) * 4] = struct.pack("<I", fat_start + i if i < nfat else FREESECT)
    return bytes(header) + b"".join(sectors)


def ovba_compress(data: bytes) -> bytes:
    """MS-OVBA Compression algorithm — uncompressed chunks (flag clear)."""
    out = bytearray([0x01])
    for i in range(0, max(len(data), 1), 4096):
        chunk = data[i : i + 4096]
        header = 0x3000 | 4095  # uncompressed, size 4096
        out += struct.pack("<H", header)
        out += chunk.ljust(4096, b"\0")
    return bytes(out)


def build_dir_stream(modules: list[tuple[str, str, int]], codepage: int = 1252) -> bytes:
    """Minimal MS-OVBA `dir` stream for the given modules (name, stream, offset)."""
    out = bytearray()

    def rec(id_: int, data: bytes):
        out.extend(struct.pack("<HI", id_, len(data)))
        out.extend(data)

    rec(0x0001, struct.pack("<H", 0xFFFF))
    rec(0x000C, struct.pack("<I", 0x04109F19))
    rec(0x003E, struct.pack("<I", 0x04109F19))
    rec(0x0003, struct.pack("<H", codepage))
    rec(0x0004, b"VBAProject")
    rec(0x0040, "VBAProject".encode("utf-16le"))
    rec(0x0002, b"")
    rec(0x0041, b"")
    rec(0x0005, b"C:\\")
    rec(0x003D, b"C:\\")
    rec(0x0006, struct.pack("<I", 0))
    rec(0x0007, struct.pack("<I", 0))
    out.extend(struct.pack("<HI", 0x0009, 4))
    out.extend(struct.pack("<IH", 0xFFFFFFFF, 0))
    rec(0x0008, b"")
    rec(0x003C, b"")
    rec(0x000F, struct.pack("<H", len(modules)))
    rec(0x0013, struct.pack("<H", 0xFFFF))
    for name, stream_name, offset in modules:
        rec(0x0019, name.encode("ascii"))
        rec(0x0047, name.encode("utf-16le"))
        rec(0x001A, stream_name.encode("ascii"))
        rec(0x0032, stream_name.encode("utf-16le"))
        rec(0x001C, b"")
        rec(0x0048, b"")
        rec(0x0031, struct.pack("<I", offset))
        rec(0x001D, struct.pack("<I", 0))
        rec(0x002C, struct.pack("<H", 0xFFFF))
        rec(0x0021, b"")  # MODULETYPE procedural
        rec(0x002B, b"")  # MODULEEND
    rec(0x0010, b"")
    return bytes(out)


def vba_project(modules: list[tuple[str, str]]) -> bytes:
    """Build a vbaProject.bin: modules is [(module_name, source_code), ...]."""
    # PerformanceCache is 0x10 zero bytes before compressed source (MODULEOFFSET)
    streams: dict[str, bytes] = {}
    dir_modules = []
    for name, source in modules:
        src = source.encode("ascii", errors="replace")
        # MODULEOFFSET points into the module stream past the PerformanceCache
        cache = b"\0" * 0x10
        streams[name] = cache + ovba_compress(src)
        dir_modules.append((name, name, 0x10))
    dir_raw = build_dir_stream(dir_modules)
    streams["dir"] = ovba_compress(dir_raw)
    streams["_VBA_PROJECT"] = b"\xcc\x61\xff\xff\x00\x00\x00"  # minimal magic

    def add(root: Node):
        vba = root.storage("VBA")
        for n, d in streams.items():
            vba.stream(n, d)
        root.stream("PROJECT", b"ID=\"{00000000-0000-0000-0000-000000000000}\"\r\n")
        root.stream("PROJECTwm", b"\0\0")

    return build(add)
