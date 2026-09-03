# Stage 6 — Escape (WebProcess sandbox → host)

> **Вектор A: Coruna/cassowary (iOS 16.6–17.2.1, исторический)**
> Источники: cside [11], Centripetal [12].
> ⚠️ Для iOS 26 — TODO (новые CVE).

## 6.1 Sandbox escape (Phase 4 Coruna, cassowary chain)
Комбинация двух техник [11]:
1. **SVG `<feConvolveMatrix>` filter exploit** →
   corrupt memory в **WebKit compositor process** → escape renderer sandbox
2. **`pthread_main_thread_np`** (private API) →
   получение указателя на **структуру main thread** WebContent-процесса.
   Main thread имеет доступ к compositor и shared memory →
   **обход sandbox за счёт манипуляции TLS** (НЕ kernel-привилегия).

### Уточнение по pthread_main_thread_np
- Это **не** "расширение привилегий" в kernel-смысле.
- Это получение `pthread_t` main thread → доступ к его TLS →
  shared memory с compositor → выход за пределы renderer sandbox.
- Механизм: main thread в WebContent имеет IPC-каналы к
  UIProcess/NetworkingProcess, которых нет у renderer thread.

## 6.2 ⚠️ Коррекция: чужие CVE убраны
| CVE | Цепочка | Роль | В cassowary? |
|-----|---------|------|--------------|
| CVE-2023-32409 | **IronLoader** (отдельная chain) | WebKit sandbox escape | **НЕТ** |
| CVE-2023-38606 | **Gallium** (отдельная chain) | IOKit OOB / PPL bypass | **НЕТ** |
| CVE-2023-41974 | **Photon** (отдельная chain) | Kernel UAF / privesc | **НЕТ** |
| CVE-2023-32434 | **Photon** (отдельная chain) | Kernel integer overflow | **НЕТ** |

Эти CVE — из **других цепочек** Coruna (для других iOS версий).
В **cassowary chain** sandbox escape = feConvolveMatrix + pthread_main_thread_np.
Kernel privesc в cassowary **не требуется** — после escape из WebContent
доступ к powerd/locationd через IPC + TLS.

## 6.3 PPL (Page Protection Layer)
- В cassowary: PPL bypass **не требуется** (достаточно sandbox escape).
- PPL bypass (CVE-2023-38606) — только в **Gallium chain** (iOS 14.x).
- Для iOS 26: PPL усилен, нужен новый механизм (TODO).

## TODO
- [ ] feConvolveMatrix: точный механизм corruption compositor (для iOS 26)
- [ ] pthread_main_thread_np: как именно TLS даёт IPC-каналы (детали)
- [ ] Sandbox profile WebProcess (seatbelt) для iOS 26
- [ ] Альтернатива feConvolveMatrix для iOS 26 (если SVG-баг закрыт)
