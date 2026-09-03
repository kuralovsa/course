# Stage 2 — Trigger (fingerprinting + выбор цепочки)

> **Вектор A: Coruna/cassowary (iOS 16.6–17.2.1, ИСТОРИЧЕСКИЙ)**
> Источники: cside [11], Centripetal [12].
> ⚠️ Для iOS 26 — исторический материал.

## 2.1 Fingerprinting (Phase 1 Coruna)
1. **UA check**: `Version/` + `AppleWebKit/` (иначе stop) [11]
2. **iOS vs macOS**: `typeof TouchEvent !== "undefined"` +
   IndexedDB Blob test (iOS бросает `"BlobURLs are not yet supported"`) [11]
3. **WebAssembly memory oracle** (самое тонкое):
   - `WebAssembly.Table` + `WebAssembly.Instance`
   - читает **JSC cell type tags** из памяти:
     - `0x10016` = macOS Safari
     - `0x10017` = iOS Safari [11]
   - требует интимного знания WebKit source
4. **Версия iOS**: из UA → lookup 19 iOS (10.0.0–17.0.0) + 13 macOS Safari
   → отдельные пути для iOS 13–15.x и iOS 16.x+ [11]

## 2.2 Выбор exploit chain
- 12 именованных цепочек, 23 эксплойта, покрытие iOS 13.0–17.2.1 без пробелов [11][12]
- **cassowary (CVE-2024-23222)** = primary chain, iOS 16.6–17.2.1 [11][12]
- NadSec: **3 независимых WebKit RCE пути** (выбор по платформе/версии) [12]:
  - NaN-boxing type confusion (macOS)
  - JIT structure check elimination + Web Worker retry (macOS fallback)
  - OfflineAudioContext heap corruption + SVG attribute manipulation (iOS)
  - все сходятся в общий arbitrary R/W primitive

## 2.3 Version-adaptive offsets
- NadSec: **41 JSC internal structure offset** across 3 WebKit version thresholds
  → систематический доступ к нескольким WebKit-сборкам при разработке [12]
- Для нашего harness: offsets JSCell header зависят от версии WebKit (TODO)

## 2.4 Триггер JIT (для cassowary)
- Функция вызывается **1,000,000 раз** с float-аргументами →
  JIT специализирует под float array [11]
- (в нашем harness: `jitIterTotal = 0x1000000`, `slow(12)` для race window)

## TODO
- [ ] Wasm memory oracle: воспроизвести чтение JSC cell tags (0x10016/0x10017)
- [ ] 41 offset: извлечь из Coruna JS (если есть sample)
