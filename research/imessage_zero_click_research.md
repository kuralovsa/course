# Вектор Б — iMessage zero-click (для ios26_imessage_rce.py)

> **ОТДЕЛЬНЫЙ вектор от Coruna/cassowary (Вектор A).**
> ⚠️ Статус: **ГИПОТЕЗА + TODO** — данных мало, web search пуст.
> Для iOS 26 нужны **свежие** (2025-2026) уязвимости в iMessage-компонентах.

## 1. Почему отдельный вектор
- **Вектор A (Coruna):** Safari iframe → WebKit RCE → sandbox escape → имплант.
  iMessage = только C2-канал (imagent backup). [11][12]
- **Вектор Б (iMessage zero-click):** iMessage payload → iMessage-демон
  (imagent / IMTranscoderAgent / IMCore) → WebProcess или напрямую → RCE.
  iMessage = **delivery + trigger**.
- Это **разные** delivery, trigger, и (вероятно) разные CVE.

## 2. Кандидатные компоненты iMessage (по знаниям, TODO верификация)
| Компонент | Роль | Типичные баги |
|-----------|------|---------------|
| **imagent** | iMessage daemon, C2-канал в Coruna | IPC, UAF |
| **IMTranscoderAgent** | транскодирование media | parser, OOB |
| **IMCore** | ядро iMessage | logic, UAF |
| **WebKit (WKWebView)** | rich content / link preview | JSC type confusion |
| **IMTransferService** | передача файлов | IPC, UAF |

## 3. Кандидатные CVE (по знаниям, ⚠️ старость — проверить актуальность для iOS 26)
| CVE | Компонент | Тип | Год | Актуально для iOS 26? |
|-----|-----------|-----|-----|----------------------|
| CVE-2023-41974 | kernel (XNU) | UAF | 2023 | **НЕТ** (закрыт iOS 17) |
| CVE-2023-38606 | IOKit | OOB write | 2023 | **НЕТ** (закрыт) |
| CVE-2023-32434 | kernel | integer overflow | 2023 | **НЕТ** (закрыт) |
| CVE-2024-23222 | WebKit JSC | type confusion | 2024 | **НЕТ** (закрыт iOS 17.3) |
| **TODO** | iMessage 2025-2026 | ? | 2025-2026 | **ИСКАТЬ** |

**Вывод:** все известные iMessage-adjacent CVE **закрыты до iOS 17.3**.
Для iOS 26 нужен **fuzzing-ориентированный** поиск новых багов,
а не эксплуатация известных.

## 4. Zero-click механизм (гипотеза, TODO верификация)
```
[получение iMessage]  (0 tap)
   |
   v
imagent / IMTranscoderAgent  (разбор attachments)
   |  тип = URL / sticker / effect / media
   v
[подъём WebProcess]  (WKWebView для rich content / preview)
   |
   v
JSC исполняет JS payload → JIT → type confusion
   |
   v
RCE в WebProcess → sandbox escape → host
```
**Открытые вопросы:**
- Какой контент-тип поднимает WebProcess без tap на iOS 26?
- Исполняется ли JS в link preview на iOS 26?
- Какой selector в imagent поднимает WKWebView?
- Нужен ли kernel privesc или достаточно WebProcess RCE?

## 5. Отличие от Вектора A (сводка)
| Аспект | Вектор A (Coruna) | Вектор Б (iMessage) |
|--------|-------------------|---------------------|
| Delivery | Safari iframe | iMessage payload |
| Trigger | page load (UI:R) | 0-click (получение) |
| RCE | WebKit JSC (cassowary) | WebKit JSC / IMTranscoderAgent |
| Sandbox escape | feConvolveMatrix + pthread | TODO |
| iMessage роль | C2-канал | delivery + trigger |
| iOS 26 актуальность | **НЕТ** (история) | **ИСКАТЬ** (fuzzing) |

## 6. TODO (приоритет)
- [ ] **Fuzzing** iMessage-компонентов (imagent, IMTranscoderAgent, IMCore) на iOS 26
- [ ] Свежие CVE 2025-2026 в iMessage/WebKit (Apple security releases)
- [ ] Zero-click: какой контент поднимает WebProcess без tap (iOS 26)
- [ ] Sandbox escape для iMessage-вектора (альтернатива feConvolveMatrix)
- [ ] Нужен ли kernel privesc (или достаточно WebProcess RCE)
- [ ] Reboot-persistence: нужен ли (launchd/MDM)
