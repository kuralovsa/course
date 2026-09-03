# Структура изучения + актуальная архитектура

> ⚠️ **ВАЖНО:** Архитектура ниже — для **iOS 16.6–17.2.1** (Coruna/cassowary).
> Для **iOS 26** это **исторический** материал. Все CVE закрыты.
> Для iOS 26 нужен **fuzzing-ориентированный** поиск новых багов.

## 1. ДВА ВЕКТОРА (чёткое разделение)

### Вектор A: Coruna/cassowary (Safari) — ИСТОРИЯ
```
[Delivery]  Safari iframe (watering hole)
   |  hidden zero-dim <iframe>, 4-layer obfuscation
   v
[Trigger]   Fingerprinting (Wasm oracle: JSC cell tags 0x10016/0x10017)
   |  12 chains / 23 exploits, iOS 13.0–17.2.1
   v
[Bug fire]  cassowary = CVE-2024-23222 (iOS 16.6–17.2.1)
   |  JSC DFG JIT type confusion
   v
[Primitive] addrof + fakeobj → fake ArrayBuffer → arbitrary R/W
   v
[Escalation] ASLR (dyld scan) + PAC bypass + RWX (mach_vm_allocate)
   v
[Escape]    SVG feConvolveMatrix + pthread_main_thread_np
   |  (НЕ kernel CVE — это sandbox escape, не privesc)
   v
[Implant]   ARM64 shellcode → Mach-O → PlasmaLoader
   |  powerd(root) → locationd → imagent(C2) → SpringBoard
   |  iMessage = C2-канал (backup), НЕ delivery
   v
[RCE + exfil]  (in-session injection, no reboot persistence)
```
**Статус для iOS 26: НЕ АКТУАЛЕН** (все CVE закрыты до iOS 17.3/17.4).

### Вектор Б: iMessage zero-click — ДЛЯ НАШЕГО FRAMEWORK
```
[Delivery]  iMessage payload (0-click)
   |
   v
[Trigger]   imagent / IMTranscoderAgent (разбор attachments)
   |  → подъём WebProcess (WKWebView)
   v
[Bug fire]  JSC type confusion / IMTranscoderAgent parser
   |  (какой CVE для iOS 26 — TODO, fuzzing)
   v
[Primitive] OOB R/W (аналогично Вектору A)
   v
[Escape]    sandbox escape (TODO: альтернатива feConvolveMatrix)
   v
[Implant]   (TODO: reboot-persistence или in-session)
```
**Статус для iOS 26: ГИПОТЕЗА + FUZZING** (нет свежих CVE).

## 2. Ключевые коррекции (vs ранние версии файлов)

| # | Было | Стало |
|---|------|-------|
| 1 | "для cassowary delivery = Safari" (смешано с iMessage) | **Вектор A = Safari, Вектор Б = iMessage** (раздельно) |
| 2 | CVE-2023-38606/41974 в stage6 (cassowary) | **Убраны** — это Gallium/Photon, не cassowary |
| 3 | pthread_main_thread_np = "расширение привилегий" | **Получение main thread struct → TLS → IPC** (sandbox escape, не kernel) |
| 4 | stage7 = "persistence" | **In-session daemon injection** (no reboot persistence) |
| 5 | DGA = основной C2 | **DGA = fallback** (если hardcoded C2 недоступны) |
| 6 | iOS 26 актуальность | **История для iOS 16-17**, для iOS 26 — fuzzing |

## 3. Структура файлов (обновлённая)

```
research/
├── README.md                        # индекс + предупреждение об устаревании
├── safari_delivery_coruna.md        # Вектор A: Stage 1 (Safari delivery)
├── stage2_trigger.md                # Вектор A: Stage 2 (fingerprinting)
├── stage3_bugfire.md                # Вектор A: Stage 3 (cassowary)
├── stage4_primitive.md              # Вектор A: Stage 4 (R/W)
├── stage5_escalation.md             # Вектор A: Stage 5 (ASLR/PAC/RWX)
├── stage6_escape.md                 # Вектор A: Stage 6 (sandbox escape)
├── stage7_persistence.md            # Вектор A: Stage 7 (implant/exfil)
├── imessage_zero_click_research.md  # ВЕКТОР Б: iMessage zero-click
└── study_structure_architecture.md  # этот файл (структура + архитектура)
```

## 4. Методология (что сработало)
1. Web search пуст → `fetch_url` по точечным источникам.
2. NVD JSON → структурированные факты.
3. Apple release notes → официальные формулировки + Bugzilla.
4. fulldisclosure → PGP-подписанные APPLE-SA.
5. CISA KEV → подтверждение эксплуатации.
6. Threat-intel writeup (cside, Centripetal) → 6-фазная цепочка.
7. Bugzilla → login (TODO).

## 5. Уверенность по этапам (Вектор A)
| Этап | Уверенность | Примечание |
|------|-------------|------------|
| 1. Delivery (Safari) | высокая | cside, Centripetal |
| 2. Trigger | высокая | cside, Centripetal |
| 3. Bug fire | **максимальная** | NVD, Apple, CISA |
| 4. Primitive | высокая | cside, Centripetal |
| 5. Escalation | высокая | cside, Centripetal |
| 6. Escape | высокая (механизм) | cside, Centripetal |
| 7. Implant | высокая | cside, Centripetal |
| **Вектор Б (iMessage)** | **НИЗКАЯ** | гипотеза, fuzzing TODO |

## 6. Открытые вопросы (TODO)
### Вектор A (история, для понимания)
- [ ] Bugzilla 267134 полный текст (login)
- [ ] 41 JSC offset (из Coruna JS sample)
- [ ] feConvolveMatrix: точный механизм (для старых версий)

### Вектор Б (iOS 26, приоритет)
- [ ] **Fuzzing** iMessage-компонентов (imagent, IMTranscoderAgent, IMCore)
- [ ] Свежие CVE 2025-2026 (Apple security releases)
- [ ] Zero-click: какой контент поднимает WebProcess без tap (iOS 26)
- [ ] Sandbox escape для iMessage-вектора
- [ ] Reboot-persistence: нужен ли (launchd/MDM)
- [ ] PAC/PPL для iOS 26 (новые механизмы)

## 7. Вывод для framework (ios26_imessage_rce.py)
- Framework строится вокруг **Вектора Б** (iMessage zero-click).
- Вектор A (Coruna) = **историческая база** для понимания механики
  (JIT type confusion, sandbox escape, implant).
- Для iOS 26: **fuzzing-ориентированный** подход (нет свежих CVE).
- Delivery-стадия framework = iMessage (не Safari).
- Upgrade-стадии (4-7) **универсальны** для обоих векторов.
