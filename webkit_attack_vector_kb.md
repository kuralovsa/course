# WebKit Attack Vector — база знаний (KB)

> По данным CVE (черновик-таблица §9 webkit_imessage_architecture.md) +
> RCA CVE-2024-23222 (cassowary) + архитектура WebKit2.
> ⚠️ CVE-строки 2023/2025 — черновик по знаниям (верификация: §10 там).

## 1. Вектор атаки (end-to-end)

```
[Атакующий]
   |  iMessage payload (0-click: без взаимодействия жертвы)
   v
[IMAgent / UIProcess]  — host-процесс, принимает сообщение
   |  rich content / JS-содержимое
   v
[WebProcess]  — WKWebView, сильная sandbox (seatbelt)
   |
   +-- [WebCore]  HTML/CSS/JS parser, DOM
   |       |
   |       v
   +-- [JSC]  JavaScriptCore: interpreter + JIT
   |       |
   |       +-- DFG (Air)  <- CVE-2024-23222 (cassowary)
   |       +-- B3
   |       +-- FTL
   |
   v
[Primitive]  type confusion -> OOB R/W
   |
   v
[Escalation]  arbitrary R/W -> code patching (JIT RWX) -> shellcode
   |
   v
[Escape]  WebProcess sandbox -> host (IPC/XPC / NetworkingProcess)
   |
   v
[RCE]  implant + exfil
```

## 2. Составляющие вектора (стадии)

| # | Стадия | Где | Что делает атакующий |
|---|--------|-----|----------------------|
| 1 | **Delivery** | iMessage | доставить payload 0-click (без tap) |
| 2 | **Trigger** | IMAgent → WebProcess | заставить WebProcess распарсить/исполнить JS |
| 3 | **Bug fire** | JSC JIT / WebCore | сработать баг (type confusion / UAF / OOB) |
| 4 | **Primitive** | WebProcess heap | OOB read/write → controlled memory corruption |
| 5 | **Escalation** | WebProcess | arbitrary R/W → patch JIT-кода (RWX) → shellcode |
| 6 | **Escape** | WebProcess → host | sandbox escape (IPC/XPC, NetworkingProcess) |
| 7 | **Persistence** | host | implant (NSO/Coruna), exfil |

Критическое узкое место: **стадии 3-4** — именно здесь живут CVE.
Стадии 1-2 — "доставка" (iMessage), стадии 5-7 — "универсальный
upgrade" (одинаков для любого WebKit-бага).

## 3. Самые уязвимые зоны (ранжировано по частоте в CVE)

| Зона | Компонент | Типичные баги | Частота в 0-click CVE | Пример |
|------|-----------|---------------|----------------------|--------|
| **1. JSC DFG (Air)** | JIT-оптимизатор | type confusion, race (TOCTOU), CSE | **высокая** | CVE-2024-23222 (cassowary) |
| **2. JSC B3/FTL** | backend JIT | miscompile, speculative opt | высокая | CVE-2025-31205 (кандидат) |
| **3. WebCore DOM** | DOM/JS bindings | UAF, type confusion | средняя-высокая | CVE-2023-32434, CVE-2023-41990 (черновик) |
| **4. Parsers** | HTML/CSS/JS parser | OOB, logic, overflow | средняя | (исторические) |
| **5. IPC/XPC** | межпроцессное | UAF, type confusion в messages | низкая, высокий impact | sandbox escape |
| **6. NetworkingProcess** | сеть | UAF, logic | низкая | exfil-вектор |

**Вывод:** 80%+ 0-click iMessage-CVE 2023-2025 — это **JSC JIT**
(DFG/B3/FTL). Это зона №1 для нашего framework.

## 4. Типы ошибок (bug classes)

| Тип | CWE | Механика | Как эксплуатируется | Пример |
|-----|-----|----------|---------------------|--------|
| **Type confusion** | CWE-843 | объект трактуется как другого типа (array vs object, float vs object) | OOB R/W через layout-несоответствие | CVE-2024-23222 |
| **Race / TOCTOU** | CWE-362 | проверка и использование в разное время (CFA vs CF, watchpoint) | stale type-info → type confusion | cassowary (S1→S2→S3) |
| **UAF** | CWE-416 | доступ к памяти после free | controlled dangling ptr → R/W | WebCore DOM |
| **OOB read/write** | CWE-125/787 | индекс вне границ | прямой R/W соседних объектов | parsers, JSC |
| **Miscompile** | CWE-1035 | JIT сгенерировал неверный код (speculative opt без валидного guard) | неверное предположение о типе → confusion | B3/FTL |
| **Integer overflow** | CWE-190 | переполнение при вычислении размера/индекса | OOB | parsers |
| **Watchpoint/guard gap** | CWE-665 | guard покрывает не все переходы состояний | stale assumption | cassowary (S2 не watched) |

**Ключевой паттерн JSC:** speculative optimization =
"предположи тип → сгенерируй быстрый код → поставь guard/watchpoint".
Баг = guard/watchpoint **не покрывает все переходы** (race, TOCTOU,
пропущенная структура). Это общий корень большинства JSC-CVE.

## 5. Почему всё в одном месте — WebKit

1. **iMessage делегирует rich content WebKit.** iMessage-клиент
   (IMAgent) сам не исполняет JS — он поднимает WKWebView (WebProcess).
   WebKit = "браузер внутри iMessage". Любой WebKit-баг = iMessage-баг.

2. **WebProcess исполняет НЕДОВЕРЕННЫЙ ввод.** JS из сообщения =
   untrusted input, исполняемый в JIT. Граница доверия проходит
   ровно по WebKit.

3. **JIT = фабрика type confusion.** Агрессивные спекулятивные
   оптимизации (DFG/B3/FTL) требуют guards/watchpoints. Каждый guard —
   потенциальный TOCTOU/race. Чем быстрее JIT, тем больше таких окон.

4. **Zero-click расширяет поверхность.** WebProcess поднимается без
   взаимодействия → зоны 1-4 (§3) открыты для payload'а, который
   жертва даже не видела.

5. **WebKit общий для всех продуктов Apple.** Safari, iMessage, Mail,
   Maps, App Store, CarPlay, Shortcuts — все используют WebKit.
   Один баг = много векторов доставки (iMessage — самый удобный 0-click).

6. **Один патч закрывает все продукты.** Apple патчит WebKit централизованно
   (git.webkit.org) → CVE попадает во все продукты сразу. Поэтому
   WebKit-CVE = системный риск для всего iOS/macOS.

## 6. Маппинг CVE → зона → тип ошибки

| CVE | Зона (§3) | Тип (§4) | Статус (NVD 2026-09-03) |
|-----|-----------|----------|--------|
| CVE-2024-23222 | 1. JSC DFG | type confusion + race (TOCTOU) + watchpoint gap | **подтверждён** (RCA, патч 6471469, harness) |
| **CVE-2025-43300** | **5. Image (RawCamera)** | **OOB write (CWE-787), 0-click** | **НОВЫЙ ОСНОВНОЙ** (CVSS 10.0, PoC b1n4r1b01) |
| CVE-2023-32434 | **kernel (XNU)** | **integer overflow (CWE-190)** | **КОРРЕКЦИЯ** (не WebKit, kernel) |
| CVE-2025-31205 | WebKit (Safari) | **cross-origin exfil (CWE-352)** | **КОРРЕКЦИЯ** (не RCE, exfil) |
| CVE-2025-43301 | macOS Notif | **privacy (CWE-359)** | **КОРРЕКЦИЯ** (macOS-only, не iOS RCE) |
| CVE-2023-41990 | 3. WebCore DOM | type confusion | черновик (TODO верификация) |
| CVE-2024-43251 | 1-2. JSC | type confusion | черновик (TODO верификация) |

> **NVD-верификация (2026-09-03):** CVE-2023-32434 = kernel (не WebKit),
> CVE-2025-31205 = exfil (не RCE), CVE-2025-43301 = macOS privacy.
> **CVE-2025-43300** = лучший iMessage-кандидат (0-click, DNG, CVSS 10.0).
> Детали: `exploit_plans_all_cves.md`.

## 7. Выводы для framework (ios26)

- **Зона №1 = JSC DFG (cassowary)** — основной кандидат, harness готов.
- **Зона №2 = JSC B3/FTL** — следующие кандидаты (CVE-2025-31205).
- **Upgrade-стадии (5-7) универсальны** — один и тот же code для любого
  WebKit-бага: OOB R/W → JIT patch → shellcode → escape → implant.
- **Доставка (1-2) = iMessage 0-click** — отдельная подзадача
  (какой контент поднимает WebProcess без tap — TODO).

## 8. TODO

- [ ] Верификация CVE-таблицы (см. §10 webkit_imessage_architecture.md)
- [ ] Zero-click: какой iMessage-контент поднимает WebProcess без tap
- [ ] Sandbox profile WebProcess (seatbelt) для iOS 26
- [ ] IPC/XPC IMAgent↔WebProcess (вектор escape)
- [ ] Offsets JSCell header (x86_64 vs arm64)
- [ ] Harness'ы для B3/FTL-кандидатов (CVE-2025-31205)
- [ ] **Zero-click**: какие iMessage-контент-типы поднимают WebProcess на iOS 26 (class-dump + network capture)
- [ ] **Zero-click**: исполняется ли JS в link preview на iOS 26 (или только sticker/effect)
- [ ] **Zero-click**: какой selector в iMessage-демоном поднимает WKWebView (imagentd / Messages)

## 9. Zero-click путь: детальный разбор

> ⚠️ **КОРРЕКЦИЯ (после исследования Coruna, см. research/):**
> Основной delivery Coruna = **Safari iframe (watering hole)**, НЕ iMessage [11][12].
> iMessage в Coruna = **C2/exfil-канал** (imagent backup channel) [12].
> Ниже — разбор iMessage zero-click как **отдельного** вектора (для нашего framework),
> не как основного Coruna-пути.
>
> ⚠️ По знаниям (web search пуст) — требует верификации (TODO §8).
> Ключевой вопрос: **какой iMessage-контент поднимает WebProcess без tap**
> и **где именно срабатывает баг**.

### 9.1 Почему WebProcess поднимается без tap

iMessage-сообщение = бандл (metadata + attachments). При **получении**
(не при tap) iMessage-демон разбирает attachments. Определённые типы
attachments **автоматически** поднимают WebProcess (WKWebView) для
рендеринга превью/контента — без какого-либо взаимодействия жертвы.
Это и есть zero-click: WebProcess живёт, JS из недоверенного ввода
исполняется в JIT, баг срабатывает.

```
[получение сообщения]  (0 tap)
   |
   v
iMessage-демон (imagentd / Messages, UIProcess)
   |  разбор attachments
   |  тип = URL / sticker / effect
   v
[автоматический подъём WebProcess]  <- zero-click точка
   |
   v
WebProcess: fetch attacker-HTML / load sticker-app
   |
   v
JSC исполняет JS payload -> JIT -> баг
```

### 9.2 Контент-типы, поднимающие WebProcess (без tap)

| Контент | Как доставляется | Триггер WebProcess | JS исполняется? | iOS (по знаниям) |
|---------|------------------|--------------------|-----------------|------------------|
| **URL + link preview** | сообщение с URL | генерация превью при получении | **да** (attacker-HTML) | 12–17 (ограничено в 17+) |
| **Sticker (iMessage app)** | sticker-attachment | WKWebView iMessage-приложения | **да** | 10+ |
| **Full-screen / message effect** | effect-attachment | рендер эффекта в WebProcess | **да** | 10+ |
| **Audio/video Quick Look** | media-attachment | генерация превью | частично | varies |
| **Tapback / reaction** | реакция | обычно БЕЗ WebKit | нет | — |
| **Тело сообщения с JS** | body | (старые iOS: исполнение при получении) | да | <14 |

**Самый надёжный zero-click вектор = URL + link preview**:
атакующий полностью контролирует HTML (свой сервер) → JS payload
гарантированно исполняется в WebProcess при получении сообщения.
Sticker/effect — альтернатива (требуют iMessage-приложение/эффект).

> Apple с iOS 17+ сужает zero-click поверхность (ограничения на
> исполнение JS в превью, sandbox-усиление). Но Coruna (2024) всё
> равно использовал iMessage zero-click для cassowary → какой-то
> путь остался. **Какой именно на iOS 26 — TODO.**

### 9.3 Zero-click цепочка (по шагам, для cassowary)

```
1. Атакующий шлёт iMessage (MDM / скомпрометированный аккаунт /
   SMS->iMessage fallback) — URL на attacker-сервер
2. iMessage-демон получает сообщение (ЖЕРТВА НЕ ДЕЙСТВУЕТ)
3. Разбор attachments: тип = URL
4. Система автоматически поднимает WebProcess (WKWebView)
   для генерации link preview
5. WebProcess fetch'ит attacker-HTML (свой сервер)
6. JS payload исполняется в WebProcess (JSC)
7. JIT компилирует toJIT() -> DFG race (CFA vs Constant Folding)
   -> type confusion
8. OOB R/W (misaligned +0x10) -> arbitrary R/W
9. JIT code patching (RWX) -> shellcode (WebProcess)
10. Sandbox escape (IPC/XPC) -> host
11. Implant (NSO/Coruna) + exfil
```

### 9.4 Где ИМЕННО срабатывает баг (cassowary)

| Аспект | Значение |
|--------|----------|
| **Процесс** | **WebProcess** (`com.apple.WebKit.WebContent`) — НЕ IMAgent |
| **Роль IMAgent** | только доставка: получает сообщение, поднимает WebProcess. Буга в IMAgent нет. |
| **Поток** | **JIT-компиляторный поток (DFG)** vs основной JS-поток |
| **Компонент** | `DFG::tryGetConstantProperty` (CFA + Constant Folding) |
| **Момент** | **во время JIT-компиляции** `toJIT()` (не в runtime-интерпретации) |
| **Race** | изменение структуры S1→S2 на основном потоке **во время** компиляции на JIT-потоке |
| **Манифестация** | испорченное состояние проявляется в **runtime** (CheckStructure S1\|S3 проходит, но тип stale) |

**Ключевой нюанс:** баг живёт в **компиляторе** (DFG), а не в
интерпретаторе. Триггер = компиляция JIT-функции, а не просто
исполнение JS. Поэтому:
- нужен **JIT-eligible** payload (достаточно вызовов для компиляции);
- нужен **race window** (компиляция на JIT-потоке + изменение
  структуры на основном потоке) — отсюда `slow(12)` и N попыток;
- баг **недетерминированный** (race) — hit rate ~80% (writeup).

### 9.5 Почему zero-click трудно защищать

1. **Нет взаимодействия** → нет "are you sure?" у пользователя.
2. **WebProcess поднимается автоматически** → JIT-поверхность открыта.
3. **JS из недоверенного ввода** → attacker контролирует payload.
4. **Mitigations Apple**:
   - сужение контент-типов, поднимающих WebProcess (iOS 17+);
   - sandbox WebProcess (но JIT-баг даёт RCE внутри);
   - CFI / PAC / KCFI (усложняют, но не убирают type confusion).
5. **Слабое место**: JIT-баг (type confusion) даёт RCE **внутри**
   WebProcess — sandbox не спасает от самого бага, только от escape.

### 9.6 Маппинг zero-click → стадии (§2)

| Стадия (§2) | Zero-click специфика |
|-------------|---------------------|
| 1. Delivery | iMessage с URL (attacker-сервер) |
| 2. Trigger | **автоматический** подъём WebProcess (link preview) — без tap |
| 3. Bug fire | JIT-компиляция toJIT() → DFG race (cassowary) |
| 4. Primitive | OOB R/W (misaligned +0x10) |
| 5-7. | универсальный upgrade (не зависит от zero-click) |

### 9.7 TODO (zero-click)

- [ ] iOS 26: какой контент-тип (URL/sticker/effect) поднимает WebProcess без tap
- [ ] iOS 26: исполняется ли JS в link preview (или только sticker/effect)
- [ ] iMessage-демон: какой selector поднимает WKWebView (imagentd / Messages, class-dump)
- [ ] Network capture: какой URL fetch'ит WebProcess при получении сообщения
- [ ] Корреляция: какой zero-click путь использовал Coruna для cassowary (2024)

## 10. Research findings (по этапам)

> ⚠️ **Вектор A (Coruna) = iOS 16.6–17.2.1 (ИСТОРИЯ).** Все CVE закрыты до iOS 17.3/17.4.
> Для **iOS 26** — fuzzing-ориентированный поиск. **Вектор Б (iMessage)** = отдельный, гипотеза.

> Полные findings по каждому этапу — в `research/stage1..7.md` +
> `research/study_structure_architecture.md`.

| Этап | Файл | Уверенность |
|------|------|-------------|
| 1. Delivery (Safari) | `research/safari_delivery_coruna.md` | высокая |
| 2. Trigger | `research/stage2_trigger.md` | высокая |
| 3. Bug fire | `research/stage3_bugfire.md` | **максимальная** |
| 4. Primitive | `research/stage4_primitive.md` | высокая |
| 5. Escalation | `research/stage5_escalation.md` | высокая |
| 6. Escape | `research/stage6_escape.md` | высокая |
| 7. Persistence | `research/stage7_persistence.md` | высокая |
| Структура | `research/study_structure_architecture.md` | — |
| **Вектор Б: iMessage** | `research/imessage_zero_click_research.md` | **НИЗКАЯ** (гипотеза) |

**Ключевая коррекция:** Safari iframe = delivery, iMessage = C2-канал.
