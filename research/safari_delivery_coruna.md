# Stage 1 — Delivery (Safari / watering hole)

> **Вектор A: Coruna/cassowary (iOS 16.6–17.2.1, ИСТОРИЧЕСКИЙ)**
> ⚠️ Это **Safari-доставка**, НЕ iMessage. Для iMessage-вектора см.
> `imessage_zero_click_research.md`.
> Источники: cside [11], Centripetal [12], NVD [1].
> ⚠️ Для iOS 26 — исторический материал (delivery-инфраструктура 2025-2026).

## 1.1 Формат payload
- Self-contained **HTML-файл** (обычно `group.html` / `analytics.html`),
  вшитый как **hidden zero-dimension `<iframe>`** в веб-страницу [11].
- Эксплуатация **entirely in browser, in JavaScript**, завершается за секунды [11].
- 4 слоя обфускации [11]:
  - Layer 0: bootstrap, строки = XOR-массивы целых (`[107,49,105,97].map(x=>String.fromCharCode(x^84))`), `new Function(atob("..."))`
  - Layer 1: module dispatcher `globalThis.vKTo89` (SHA-256 + lookup по SHA1-хешам)
  - Layer 2: каждый модуль Base64 + XOR-строки
  - Layer 3: бинарные пейлоады Base64 / UTF-16LE padding (ARM64 shellcode, Mach-O)

## 1.2 Векторы доставки
| Вектор | Механика |
|--------|----------|
| Watering hole | скомпрометированный сайт (fake crypto/gambling/bingo) |
| Ad network | malicious creative через programmatic ads |
| Third-party script | supply-chain (analytics, chat widget, CDN) |
| CDN cache | poisoned CDN asset (tubeluck[.]com, 668ddf[.]cc) |

Ключевое: payload = JS-файл, "идёт туда, где идёт JS" — атакующему не нужно
владеть delivery-сайтом [11].

## 1.3 Module delivery protocol
- `LBrh4t(hash)`: filename = `SHA256(salt + hash_id).substring(0,40)`
- Salt в samples: `cf40de81867d2397` [11]
- Base URL = `location.href.slice(0, lastIndexOf("/")+1)` (тот же домен)
- API: `WLEBfI(url)`, `ksQccv(salt)`, `OLdwIx(hash)`, `LBrh4t(hash)`, `tI4mjA(hash,b64)` [11]
- NadSec: модули = SHA-1 hash identifiers + dependency resolution; бинары
  `.min.js`, ChaCha20, header `0xf00dbeef`, LZW [12]

## 1.4 Anti-analysis (до запуска эксплойта)
- abort при **Lockdown Mode** [11][12]
- skip при **private browsing** [11]
- проверка реального WebKit: `<math mathcolor="blue">` → `rgb(0,0,255)` [11]
- проверка `RTCPeerConnection` (не headless sandbox) [11]
- NadSec: проверка Corellium (virtualized iOS), удаление crashlogs
  (WebContent/powerd/kernel) после неудачных попыток [12]

## 1.5 C2-отчёт о результате
- `GET <base_url>?e=<code>`: 0=success, 1000=exploit fail,
  1001=version unsupported, 1003=sandbox detected [11]

## 1.6 ⚠️ КОРРЕКЦИЯ: Safari ≠ iMessage
- **Coruna delivery = Safari iframe (watering hole)** [11][12].
- NVD CVSS: `UI:R` (user interaction REQUIRED) — page load в Safari [1].
- **iMessage zero-click = Вектор Б** (отдельный, другой набор CVE).
- iMessage в Coruna = **C2-канал** (imagent backup), НЕ delivery [12].
- Для iOS 26 iMessage-вектора: см. `imessage_zero_click_research.md`.

## TODO
- [ ] iOS 26: актуальная delivery-инфраструктура (если Coruna-подобный kit)
- [ ] iMessage delivery: см. `imessage_zero_click_research.md`
