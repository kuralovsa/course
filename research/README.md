# research/ — findings по этапам атаки

> ⚠️ **ПРЕДУПРЕЖДЕНИЕ:** Вектор A (Coruna/cassowary) — **исторический**
> материал для **iOS 16.6–17.2.1**. Все CVE закрыты до iOS 17.3/17.4.
> Для **iOS 26** нужен **fuzzing-ориентированный** поиск новых багов.
> Вектор Б (iMessage zero-click) — **гипотеза + TODO** (нет свежих CVE).

## Два вектора (чёткое разделение)

| | Вектор A (Coruna) | Вектор Б (iMessage) |
|---|---|---|
| Delivery | Safari iframe | iMessage payload (0-click) |
| RCE | CVE-2024-23222 (cassowary) | TODO (fuzzing) |
| iMessage роль | C2-канал | delivery + trigger |
| iOS 26 | **НЕ АКТУАЛЕН** | **ИСКАТЬ** |

## Файлы

| Файл | Вектор | Этап | Уверенность |
|------|--------|------|-------------|
| `safari_delivery_coruna.md` | A | 1. Delivery (Safari) | высокая |
| `stage2_trigger.md` | A | 2. Trigger (fingerprinting) | высокая |
| `stage3_bugfire.md` | A | 3. Bug fire (cassowary) | **максимальная** |
| `stage4_primitive.md` | A | 4. Primitive (R/W) | высокая |
| `stage5_escalation.md` | A | 5. Escalation (ASLR/PAC/RWX) | высокая |
| `stage6_escape.md` | A | 6. Escape (sandbox) | высокая |
| `stage7_persistence.md` | A | 7. Implant/Exfil | высокая |
| `imessage_zero_click_research.md` | **Б** | iMessage zero-click | **НИЗКАЯ** (гипотеза) |
| `study_structure_architecture.md` | — | Структура + архитектура | — |

## Ключевые коррекции (vs v1)
1. **Вектор A (Safari) ≠ Вектор Б (iMessage)** — раздельно.
2. CVE-2023-38606/41974/32409/32434 — **не cassowary** (Gallium/Photon/IronLoader).
3. `pthread_main_thread_np` = sandbox escape (TLS/IPC), **не** kernel privesc.
4. Stage 7 = **in-session daemon injection**, не reboot-persistence.
5. DGA = **fallback** C2 (если hardcoded недоступны).
6. Для iOS 26 — **fuzzing**, не эксплуатация известных CVE.

## Источники
- NVD: services.nvd.nist.gov (CVE-2024-23222 JSON)
- Apple: support.apple.com (HT207584, 120304)
- fulldisclosure: seclists.org (APPLE-SA 01-22-2024)
- CISA: cisa.gov KEV
- cside: cside.com/blog/inside-coruna-web-script-ios-exploit
- Centripetal: centripetal.ai/threat-research/coruna-ios-exploit-kit

## Новые файлы (2026-09-03, направление A — патчи + exploit-планы)

| Файл | Назначение |
|------|-----------|
| `../CVE-2024-23222_patch_analysis.md` | **Детальный разбор патча 6471469** (DO/AFTER, визуализация, атакующие точки) |
| `../exploit_plans_all_cves.md` | **Exploit-планы по всем CVE** (NVD-верификация 2026-09-03) |

**Ключевые находки (NVD-верификация):**
- CVE-2024-23222 (cassowary) = подтверждён, патч 6471469 разобран, harness точный.
- **CVE-2025-43300** = НОВЫЙ ЛУЧШИЙ КАНДИДАТ для iMessage (0-click, DNG, OOB write, CVSS 10.0, PoC b1n4r1b01).
- CVE-2023-32434 = kernel (не WebKit), CVE-2025-31205 = exfil (не RCE), CVE-2025-43301 = macOS privacy.
