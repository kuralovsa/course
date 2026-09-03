# Stage 7 — Implant / Exfil (post-RCE)

> **Вектор A: Coruna/cassowary (iOS 16.6–17.2.1, исторический)**
> Источники: cside [11], Centripetal [12].
> ⚠️ Для iOS 26 — TODO (новые CVE, новые демоны).

## 7.1 Бинарные компоненты (stager)
| Компонент | Размер | Формат | Роль |
|-----------|--------|--------|------|
| ARM64 shellcode | 31,308 bytes | raw binary | stage-1 native exec |
| Encrypted Mach-O | 14,954 bytes | UTF-16LE padded | stage-2 native binary |
| PlasmaLoader | ~1,324 bytes (enc) | `.min.js` | final implant |
[11]

- ARM64 shellcode: prologue `STP X29, X30, [SP, #-16]!`,
  `dlsym` against `/usr/lib/system/libdyld.dylib` (runtime resolve) [11]
- Mach-O: ARM64 (`0xFEEDFACF`), references **SpringBoard, PassKitCore, CoreML,
  MediaToolbox, AppleMediaServices** → keychain, app enumeration, home screen [11]

## 7.2 Post-exploitation architecture (iVerify via Centripetal)
- **PLASMAGRID** (identifier `com.apple.assistd`) = stager [12]
- Injects into **`powerd` daemon (root)** = stage 2 [12]
- **CorePayload** в **`locationd`** process = stage 3, orchestrates [12]
- **`imagent` process** → injected module: **C2 + backup channel over SMS и iMessage** [12]
- **SpringBoard** module → communicates с locationd implant [12]
- **None code signed** [12]

## 7.3 ⚠️ Коррекция: "persistence" vs "session injection"
- **Не reboot-persistence.** Инжекты в powerd/locationd/imagent =
  **session-level injection** (живут пока демоны не перезапущены).
- **No reboot persistence**: restart clears, reinfectable [12].
- Точный термин: **in-session daemon injection** (не "persistence" в классическом
  смысле — нет launchd plist, нет disk write).
- Для iOS 26: если нужна reboot-persistence — нужен отдельный механизм
  (launchd, mobileprovision, MDM profile) — TODO.

## 7.4 Роль iMessage (коррекция)
- iMessage в Coruna = **C2/exfil-канал** (backup channel в imagent) [12],
  НЕ initial trigger.
- Initial trigger = Safari iframe (watering hole) [11].
- iMessage zero-click delivery = **Вектор Б** (отдельный, см. `imessage_zero_click_research.md`).

## 7.5 Exfil capabilities
- QR codes из images на диске [11][12]
- BIP39 seed phrases, "backup phrase", "bank account" из Apple Memos [12]
- Photos, emails, Apple Notes [12]
- Crypto wallets (18 modules): MetaMask, Trust, Phantom, Uniswap, TonKeeper,
  Exodus, Bitget, Base, WhatsApp, OKEx [11][12]
- C2: HTTPS, AES-encrypted data [12]

## 7.6 C2 infrastructure
- Hardcoded C2 domains + **DGA fallback seed "lazarus"** → 15-char `.xyz` [11][12]
- **DGA = fallback** (только если hardcoded C2 недоступны) [12]
- 27 DGA C2 domains (Cloudflare-fronted на день disclosure) [11]
- Binary payloads: `.min.js`, ChaCha20, header `0xf00dbeef`, LZW [12]

## 7.7 Forensics
- `com.apple.photolibraryd.plist` в preferences [12]
- Safari history (delivery URL) [12]
- Network activity from **powerd / imagent** в data usage logs [12]

## TODO
- [ ] powerd injection: механизм (root, no code sign) — для iOS 26
- [ ] imagent C2: SMS/iMessage backup channel (детали)
- [ ] Reboot-persistence: нужен ли для нашей цели? (launchd/MDM)
