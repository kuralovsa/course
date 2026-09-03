# iOS 26 iMessage RCE — Research

Итоговое исследование zero-click RCE на iOS 26.6.1 через iMessage.
Два вектора: **A (Coruna/cassowary — исторический, iOS 16.6–17.2.1, reference)**
и **Б (iMessage zero-click — актуальный, CVE-2025-43300)**.

## Главный документ

- **`ios26_imessage_rce_whitepaper.md`** — итоговый White Paper (автономен:
  все данные, таблицы, Mermaid-схемы, roadmap).

## Структура

| Файл | Назначение |
|------|-----------|
| `ios26_imessage_rce_whitepaper.md` | **Итоговый White Paper** |
| `CVE-2025-43300_patch_analysis.md` | Разбор патча 43300 (бинарный diff, root cause, PoC) |
| `CVE-2025-43300_backport_ios26_6_1.md` | **Backport 43300 на iOS 26.6.1** (diff RawCamera 26.6.0 vs 26.6.1 → закрыт в 26.6.0) |
| `make_dng_payload.py` | Генератор DNG-payload (2 байта) |
| `DNGViewer.m` | Crash oracle (CIRawFilter) |
| `dngviewer_crash_oracle_runbook.md` | Сценарий прогона crash oracle |
| `CVE-2024-23222_patch_analysis.md` | Детальный разбор патча 6471469 (cassowary) |
| `CVE-2024-23222_research.md` / `_map.md` | RCA + структурная карта cassowary |
| `cassowary_harness.js` | Harness на уязвимую JSC (ASSERT A/B) |
| `cassowary_lldb_commands*.txt` | LLDB-команды (2 вызова tryGetConstantProperty) |
| `run_cassowary_harness.sh` | N попыток (race window) |
| `build_vulnerable_jsc.sh` | Сборка уязвимого jsc |
| `patches/` | Revert патча + pre-patch код |
| `exploit_plans_all_cves.md` | Exploit-планы по всем CVE (NVD-верификация) |
| `webkit_attack_vector_kb.md` | KB: вектор атаки, зоны, типы ошибок |
| `webkit_imessage_architecture.md` | Архитектура WebKit x iMessage |
| `ios26_imessage_rce.py` | Оркестратор (7 стадий, --dry-run) |
| `ios26_imagent_hook.js` / `ios26_webkit_hook.js` | Frida-хуки |
| `research/` | Findings по этапам (stage1-7) + структура изучения |

## Статус (2026-09-03)

- [x] White Paper (итоговый документ)
- [x] Вектор A: RCA + патч + harness (reference chain)
- [x] Вектор Б: root cause CVE-2025-43300 + PoC + crash oracle
- [x] **Backport CVE-2025-43300 на iOS 26.6.1** — проверен: RawCamera не менялся в 26.6.0→26.6.1, фикс в 26.6.0 → **43300 закрыт на 26.6.1** (`CVE-2025-43300_backport_ios26_6_1.md`)
- [ ] Прогон crash oracle (macOS 15.6/15.6.1)
- [ ] Upgrade: OOB write → arbitrary R/W → RCE
- [ ] Fuzzing iMessage-демонов
