# iOS26 iMessage RCE — framework

> **Направление A (Coruna/cassowary) — ИСТОРИЧЕСКИЙ МАТЕРИАЛ (iOS 16.6–17.2.1).**
> Цель: исследовать ВСЕ исходники и патчи, составить harness, "угадать" патч
> (pre-patch поведение) и построить на него атаку. Весь путь записан в файлы.

## Цепочка (Вектор A — Safari/Coruna)

```
Safari iframe (watering hole)
  -> WebKit (WebKit2, stage 2: ios26_webkit_hook.js)
  -> WebKit-escape (stage 3: harness, CVE-2024-23222 cassowary)
  -> OOB read/write (stage 4)
  -> code patching / RWX (ASLR + PAC bypass, stage 5)
  -> shellcode / implant (powerd/locationd/imagent/SpringBoard, stage 6)
  -> exfil (stage 7)
```

## Цепочка (Вектор Б — iMessage zero-click, НОВЫЙ КАНДИДАТ)

```
iMessage DNG-attachment (0-click, без tap)
  -> imagent/IMTranscoderAgent (stage 2: ios26_imagent_hook.js)
  -> RawCamera.bundle: JPEG Lossless Decompression (stage 3, CVE-2025-43300)
  -> OOB write -> arbitrary R/W (stage 4)
  -> escalation (sandbox RawCamera.bundle, stage 5)
  -> sandbox escape (stage 6, TODO)
  -> implant + exfil (stage 7, TODO)
```

## Кандидаты (NVD-верификация 2026-09-03)

| CVE | Компонент | Тип | CVSS | Click | Статус |
|-----|-----------|-----|------|-------|--------|
| **CVE-2024-23222** | JSC DFG (cassowary) | type confusion (race) | 8.8 | 1-click | **REFERENCE** (harness готов, патч разобран) |
| **CVE-2025-43300** | RawCamera (DNG/JPEG) | OOB write | **10.0** | **0-click** | **НОВЫЙ ОСНОВНОЙ** (iMessage, PoC есть) |
| CVE-2023-32434 | Kernel (XNU) | integer overflow | 7.8 | 1-click | ИСТОРИЧЕСКИЙ (kernel, не WebKit) |
| CVE-2025-31205 | WebKit | cross-origin exfil | 6.5 | 1-click | ВСПОМОГАТЕЛЬНЫЙ (exfil, не RCE) |
| CVE-2025-43301 | macOS Notif | privacy | 3.3 | 1-click | НЕ ПОДХОДИТ (macOS-only) |

> **NVD-коррекции:** CVE-2023-32434 = kernel (не WebKit), CVE-2025-31205 = exfil
> (не RCE), CVE-2025-43301 = macOS privacy. CVE-2025-43300 = лучший iMessage-кандидат.

## Файлы

| Файл | Назначение |
|------|-----------|
| `ios26_imessage_rce.py` | Оркестратор (Вектор A + Б, --dry-run, --vector) |
| `ios26_imagent_hook.js` | Stage 2 (Б): hook IMAgent |
| `ios26_webkit_hook.js` | Stage 2 (A): hook WebKit/JSC, prep heap |
| `cassowary_harness.js` | Stage 3 (A): CVE-2024-23222 (reference) |
| `cassowary_lldb_commands.txt` | LLDB breakpoint (прямое утверждение) |
| `run_cassowary_harness.sh` | N попыток (race window) |
| `CVE-2024-23222_map.md` | Структурная карта CVE |
| `CVE-2024-23222_research.md` | Дип-дайс CVE + RCA |
| **`CVE-2024-23222_patch_analysis.md`** | **ДЕТАЛЬНЫЙ РАЗБОР ПАТЧА 6471469 (DO/AFTER, визуализация)** |
| **`exploit_plans_all_cves.md`** | **EXPLOIT-ПЛАНЫ ПО ВСЕМ CVE (NVD-верификация)** |
| `webkit_imessage_architecture.md` | Архитектура WebKit x iMessage + CVE-хронология |
| `webkit_attack_vector_kb.md` | KB: вектор атаки, уязвимые зоны, типы ошибок |
| `research/` | Findings по этапам (stage1-7) + актуальная архитектура |

## Запуск

```
python3 ios26_imessage_rce.py --list
python3 ios26_imessage_rce.py --dry-run --cve CVE-2024-23222          # Вектор A
python3 ios26_imessage_rce.py --dry-run --cve CVE-2025-43300          # Вектор Б
python3 ios26_imessage_rce.py --cve CVE-2024-23222 --harness cassowary_harness.js --target 10.0.0.1:9999
```

## TODO (приоритет)

### Вектор A (cassowary — reference)
- [ ] Revert патча 6471469 в jsc < 17.3 → прогнать harness (crash oracle)
- [ ] LLDB: breakpoint на tryGetConstantProperty → 2 вызова (CFA + CF)
- [ ] Offsets JSCell header (arm64 iOS vs x86_64 macOS)
- [ ] Air dump: сравнить codegen успешного/неуспешного прогона

### Вектор Б (CVE-2025-43300 — НОВЫЙ ОСНОВНОЙ)
- [x] "Commit-патч": git-коммита НЕТ (проприетарный RawCamera в dyld_shared_cache) → бинарный diff ipsw 18.6.1 vs 18.6.2: 6 функций, патч = bounds check `output > buffer_end` в `CDNGLosslessJpegUnpacker` (Quarkslab)
- [x] Root cause: SamplesPerPixel=2 (TIFF) + NumComponents=1 (SOF3) → цикл `i < width*2` + decompress() возвращает 2 → OOB write вдвое на строку
- [x] DNG-файл: точные байты (0x2FD00: 01→02, 0x3E40B: 02→01) — PoC b1n4r1b01
- [ ] Crash oracle: DNGViewer (CIRawFilter) на macOS 15.6 (vulnerable) vs 15.6.1 (patched)
- [x] **Backport на iOS 26.6.1 проверен** — RawCamera не менялся в 26.6.0→26.6.1; фикс 43300 в 26.6.0 → **закрыт на 26.6.1** (`CVE-2025-43300_backport_ios26_6_1.md`)
- [ ] Exploit chain: OOB write → arbitrary R/W → RCE
- [ ] Sandbox RawCamera.bundle (seatbelt profile)
- [ ] Интеграция в framework как stage 3 (Вектор Б)

### Общий
- [ ] PAC/PPL для iOS 26 (новые механизмы)
- [ ] Zero-click: какой контент поднимает WebProcess без tap (iOS 26)
