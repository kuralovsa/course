# ImageIO integer overflow — research (iOS 26.6.0)

> ⚠️ **Status: PoC skeleton / bug-class PoC.** The integer-overflow *class*
> (CWE-190) is verified in `imageio_int_overflow_poc.py`. The **specific**
> iOS 26.6.0 ImageIO CVE / overflow expression is **TODO** — confirm with a
> binary diff of the ImageIO TIFF decode path before treating the crash as a
> confirmed 0-day.

## 1. Bug class

**CWE-190 (integer overflow)** in the ImageIO pixel-buffer size computation.
The decoder computes the decoded size in 32-bit arithmetic:

```
size = width * height * samplesPerPixel * (bitsPerSample / 8)
```

A crafted header makes `size` wrap to a small value → the allocator reserves a
small buffer → the decoder writes the full (large) size into it → **OOB write**.

| | value |
|---|---|
| 64-bit size | `0x100020001` (~4 GB) |
| 32-bit size | `0x20001` (128 KB) ← malloc'd |
| OOB write | `0x100000000` bytes past the buffer |

## 2. Why ImageIO (attack surface)

ImageIO is the **shared image decoder** for TIFF/PNG/JPEG/HEIC/... and is
reached from many zero-click paths — including **iMessage attachments**
(Vector Б in our framework). A crafted image is decoded **on receipt**, before
any user tap, in a daemon (`imagent` / `IMTranscoderAgent`). That makes it a
strong 0-click primitive: the attacker fully controls the header (dims, SPS, BPS).

```
iMessage attachment (0-click)
  → imagent / IMTranscoderAgent
  → ImageIO (CGImageSourceCreateImageAtIndex)
  → TIFF decode: size = w*h*sps*bps/8   (32-bit)  ← OVERFLOW
  → malloc(128 KB) ; write(4 GB)        ← OOB write
  → crash / heap corruption → R/W → RCE
```

## 3. The payload (verified)

`imageio_int_overflow_poc.py` builds a little-endian **TIFF** with:

```
ImageWidth      = 0x10001
ImageLength     = 0x10001
SamplesPerPixel = 1
BitsPerSample   = 8
RowsPerStrip    = 0x10001
StripByteCounts = 0x200000 (2 MB strip data)
```

Verified read-back: `ImageWidth=0x10001 ImageLength=0x10001 SPS=1 BPS=8
RowsPerStrip=0x10001 StripBytes=0x200000` → 32-bit overflow armed.

A **control** image (0x100×0x100) is generated for the A/B oracle.

## 4. Crash oracle (A/B)

| Sample | Expected |
|---|---|
| `imageio_int_overflow_payload.tiff` | CRASH (OOB write) |
| `imageio_int_overflow_control.tiff` | no crash |

Positive = payload crashes **and** control does not. See
`imageio_int_overflow_crash_oracle.md` for local / lldb / remote runs.

## 5. Escalation path (crash → RCE)

```
OOB write (4 GB into 128 KB)
  → control the write target (heap layout / adjacent object)
  → overwrite a vtable / function pointer / length field
  → arbitrary R/W
  → code execution in the decoding daemon (imagent / IMTranscoderAgent)
  → (optional) privesc to root
```

TODO: heap-layout control to turn the OOB write into a controlled overwrite.

## 6. Fit with our framework

- **Vector Б (iMessage zero-click)** — this is a candidate **Stage 3 (bug fire)**
  for the iMessage vector, *not* the Safari/cassowary (Vector A) chain.
- Delivery = iMessage attachment; trigger = decode on receipt (0-click).
- The R/W upgrade (Stage 4-5) is **universal** — same as any WebKit/JSC bug.

## 7. TODO (version-specific, iOS 26.6.0)

- [ ] Exact overflow expression + symbol in the iOS 26.6.0 ImageIO binary
      (binary diff / `nm -m | grep -i tiff` / `otool -tv`)
- [ ] Confirm 32-bit (not 64-bit) arithmetic on the target build
- [ ] Delivery path: which daemon decodes iMessage attachments
- [ ] Crash → R/W → RCE (heap layout control)
- [ ] Map to a specific Apple advisory / HT number if one exists
