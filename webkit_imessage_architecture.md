# WebKit x iMessage — архитектура и связка

> Как iMessage использует WebKit, где проходит JS-пейлоад,
> какие процессы/песочницы задействованы и где живёт attack surface.
> (Web search пуст — карта по знаниям; версии/selector'ы TODO сверить с class-dump.)

## 1. Высокий уровень

```
iMessage (Messages.app / iMessage service)
  |
  |  входящее сообщение (SMS/iMessage payload)
  v
IMAgent  (процесс, отвечает за рендер/логику iMessage-клиента)
  |
  |  для "rich content" / JS-содержимого:
  v
WebKit2 (WKWebView / WebProcess)
  |
  |  исполнение JS
  v
JavaScriptCore (JSC)
  |
  |  JIT (DFG / Air / FTL)
  v
[attack surface: type confusion / OOB / UAF]
  |
  v
WebKit-escape -> sandbox escape -> RCE
```

## 2. Процессная модель (WebKit2)

| Процесс | Роль | Песочница |
|---------|------|-----------|
| UIProcess (IMAgent / host) | UI, WKWebView API, userContentController | слабая (host) |
| WebProcess | рендер + JS (JSC) | **сильная sandbox** (seatbelt) |
| NetworkingProcess | сеть (fetch/XHR) | средняя |
| GPUProcess | композитинг | средняя |

Ключевое: **JS исполняется в WebProcess**, а не в IMAgent.
Поэтому WebKit-баг сначала даёт RCE **внутри WebProcess sandbox**,
потом нужен **sandbox escape** (или баг в NetworkingProcess/GPUProcess).

## 3. Как iMessage попадает в WebKit

Варианты (зависят от типа контента):
1. **Tapback / rich link** — превью ссылки рендерится WebKit.
2. **iMessage App / Sticker** — JS-приложение внутри iMessage (WKWebView).
3. **Message payload** — тело сообщения с JS (в уязвимых версиях).
4. **Zero-click** — контент обрабатывается БЕЗ взаимодействия
   (самый опасный: нет tap'а, WebProcess поднимается сам).

TODO: точный путь для iOS 26 (class-dump IMAgent.framework,
проверить WKWebView / WKContentWorld / WKUserContentController).

## 4. Attack surface в WebKit/JSC

| Слой | Тип багов | Примеры |
|------|-----------|---------|
| JSC DFG (Air) | type confusion, race, CSE | CVE-2024-23222 (cassowary) |
| JSC B3 | miscompile, DFG->B3 | CVE-2025-31205 (TBD) |
| JSC FTL | speculative optimization | CVE-2025-43300/43301 (TBD) |
| WebCore DOM | UAF, type confusion | (много исторических) |
| WebProcess sandbox | escape | (редко, высокий impact) |

## 5. Эксплуатационная цепочка (zero-click)

```
1. iMessage payload -> IMAgent
2. IMAgent -> WebProcess (WKWebView) [zero-click: без tap]
3. JSC DFG JIT: type confusion (CVE-2024-23222)
4. OOB read/write (misaligned pointer, +0x10)
5. arbitrary read/write (в WebProcess)
6. code patching / RWX (JIT code)
7. shellcode (в WebProcess)
8. sandbox escape (если нужен: WebProcess -> host)
9. RCE (IMAgent / host) -> implant / exfil
```

## 6. Песочницы и что они дают

- **WebProcess sandbox**: ограничивает FS, сеть, IPC.
  WebKit-баг даёт RCE в WebProcess, но не сразу в host.
- **NetworkingProcess**: если exfil через fetch — проходит
  NetworkingProcess (сеть разрешена для iMessage).
- **Sandbox escape**: нужен для полного RCE в host
  (или использовать баг в IPC / XPC между процессами).

## 7. Связь с нашими файлами

| Файл | Место в цепочке |
|------|-----------------|
| `ios26_imagent_hook.js` | stage 1: IMAgent (UIProcess) |
| `ios26_webkit_hook.js` | stage 2: WebProcess (WKWebView) |
| `cassowary_harness.js` | stage 3: JSC DFG (CVE-2024-23222) |
| `CVE-2024-23222_map.md` | карта CVE |
| `CVE-2024-23222_research.md` | RCA CVE |
| `ios26_imessage_rce.py` | оркестратор 7 стадий |
| `webkit_attack_vector_kb.md` | KB: вектор атаки, зоны, типы ошибок, CVE-маппинг |
| `research/` | Findings по этапам (stage1-7) + структура изучения |

## 8. TODO / открытые вопросы

- [ ] Точный путь iMessage -> WebKit для iOS 26 (class-dump)
- [ ] Zero-click vs one-click: какой контент поднимает WebProcess без tap
- [ ] Sandbox profile WebProcess (seatbelt .sb) для iOS 26
- [ ] IPC/XPC между IMAgent и WebProcess (вектор sandbox escape)
- [ ] Оффсеты JSCell header (x86_64 vs arm64)
- [ ] Версии: какие iOS 26-сборки уязвимы к cassowary (17.3+ патч)

## 9. Хронология CVE iMessage+WebKit 2023-2025

> ⚠️ **ЧЕРНОВИК — по знаниям, НЕ верифицирован.**
> Источники Apple (120170, 120266) вернули 404; web search пуст.
> Только CVE-2024-23222 подтверждён глубоко (RCA + патч + harness).
> Остальные строки требуют верификации (см. §10).

| CVE | Компонент (NVD) | Тип бага (NVD) | iOS (фикс) | Click | Статус (NVD 2026-09-03) |
|-----|-----------------|----------------|-----------|-------|--------------------------|
| **CVE-2024-23222** | JSC DFG — `tryGetConstantProperty` (CFA vs Constant Folding) | type confusion (CWE-843), CVSS 8.8 | 17.3 (янв 2024) | 1-click (UI:R) | **подтверждён** (Coruna, патч 6471469, harness) |
| **CVE-2025-43300** | **RawCamera.bundle (DNG/JPEG Lossless)** | **OOB write (CWE-787), CVSS 10.0** | **18.6.2 (авг 2025)** | **0-click (UI:N)** | **НОВЫЙ ОСНОВНОЙ** (PoC b1n4r1b01, exploited) |
| CVE-2023-32434 | **Kernel (XNU)** | **integer overflow (CWE-190), CVSS 7.8** | 15.7.7 / 16.5.1 (июн 2023) | 1-click (UI:R) | **КОРРЕКЦИЯ** (kernel, не WebKit) |
| CVE-2025-31205 | WebKit (Safari) | **cross-origin exfil (CWE-352), CVSS 6.5** | 18.5 (май 2025) | 1-click (UI:R) | **КОРРЕКЦИЯ** (exfil, не RCE) |
| CVE-2025-43301 | macOS Notification Center | **privacy (CWE-359), CVSS 3.3** | macOS 14.8/15.7/26 | 1-click (UI:R) | **КОРРЕКЦИЯ** (macOS-only) |
| CVE-2023-41990 | WebKit / JavaScriptCore | type confusion | 16.7 / 17.4 | 0-click (iMessage) | черновик (TODO верификация) |
| CVE-2024-43251 | WebKit / JavaScriptCore | type confusion | 17.5 (май 2024) | 0-click (iMessage) | черновик (TODO верификация) |

### Оговорки
- Источники 120170 / 120266 — **404**, ни одну строку нельзя подтвердить цитатой из предоставленного контекста.
- **CVE-2024-23222** — единственный глубоко подтверждённый (RCA, патч `6471469`, Bugzilla 267134, harness готов).
- Строки 2023/2025 — по знаниям: компонент (JSC) + 0-click iMessage — устойчивая картина, но **точные версии фикса и тип бага** требуют сверки.
- **CVE-2025-43300/43301** — кандидаты, связь с iMessage/0-click не подтверждена.

## 10. TODO по верификации CVE-таблицы

- [ ] **HT-номера**: получить точные Apple advisory (HT-xxxxxx) по каждому CVE → вытащить официальные формулировки
- [ ] **Apple release notes**: сверить CVE-списки по версиям 16.6, 17.3, 17.5, 18.4, 18.5 (подтвердить/опровергнуть каждую строку)
- [ ] **CVE-2023-32434**: тип бага + версия фикса + 0-click (источник: Check Point / Lookout)
- [ ] **CVE-2023-41990**: тип бага + версия фикса + 0-click
- [ ] **CVE-2024-43251**: тип бага + версия фикса + 0-click
- [ ] **CVE-2025-31205**: тип бага + версия фикса + 0-click
- [ ] **CVE-2025-43300**: подтвердить/опровергнуть связь с iMessage + тип бага
- [ ] **CVE-2025-43301**: подтвердить/опровергнуть связь с iMessage + тип бага
- [ ] **Патчи**: найти commit'ы WebKit (git.webkit.org) по каждому CVE → сверить компонент JSC
- [ ] **Bugzilla**: Bugzilla-тикеты по каждому CVE (если публичные)
- [ ] **Threat-intel**: атрибуция (NSO/Coruna, Pegasus, Qaktra) по каждому 0-click CVE
- [ ] **Обновить таблицу**: после верификации снять пометку «черновик», поднять уверенность

