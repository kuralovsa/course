# Stage 5 — Escalation (ASLR → PAC → RWX)

> **Вектор A: Coruna/cassowary (iOS 16.6–17.2.1, ИСТОРИЧЕСКИЙ)**
> Источники: cside [11], Centripetal [12].
> ⚠️ PAC/PPL для iOS 26 переработаны — TODO.

## 5.1 Defeat ASLR (dyld shared cache scan)
- iOS: scan `__TEXT` headers → **WebCore, CoreUtils, IOKit** [11]
- macOS: **CoreFoundation, CoreGraphics, ActionKit, RESync** [11]
- Locate `_ZN3JSC16jitOperationListE` → JIT-выделенная executable memory [11]

## 5.2 PAC bypass (Apple Silicon)
Два описанных подхода:
- **cside [11]**: `jitCagePtr` + `SecureARM64EHashPins` →
  allocate executable memory в JIT cage + sign shellcode valid PAC.
  `new Uint32Array(10000000)` (40MB) + JIT spray `x += 1`.
- **NadSec [12]** (confused deputy): swap **unsigned GOT entries** в system
  frameworks → trigger legitimate PAC-authenticated call paths → restore.
  Не подделывает PAC, а заставляет систему подписать за атакующего.

## 5.3 JSC internal symbols (macOS stager)
```
_ZN3JSC20SecureARM64EHashPins27allocatePinForCurrentThreadEv
_ZN3JSC10LinkBuffer8linkCodeERNS_14MacroAssemblerENS_20JITCompilationEffortE
_ZN3WTF13MetaAllocator8allocateEmPv
jitCagePtr
```
[11]

## 5.4 RWX allocation
- `mach_vm_allocate` **изнутри WebContent sandbox** → RWX memory [12]

## 5.5 JIT cage code integrity
- Reimplement **PACDB rolling hash** в JS →
  использовать per-process PAC keys → valid signatures для shellcode [12]
- Kernel не отличает forged hashes от легитимных JIT-компиляций [12]

## TODO
- [ ] PACDB rolling hash: алгоритм + per-process keys (iOS 26)
- [ ] mach_vm_allocate из WebContent: права sandbox
