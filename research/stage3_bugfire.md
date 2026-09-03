# Stage 3 — Bug fire (CVE-2024-23222 cassowary)

> **Вектор A: Coruna/cassowary (iOS 16.6–17.2.1, ИСТОРИЧЕСКИЙ)**
> Источники: NVD [1], Apple [5], CISA [13], cside [11], Centripetal [12].
> ⚠️ CVE закрыт в iOS 17.3. Для iOS 26 — нужен новый баг (fuzzing).

## 3.1 Официальные факты
| Поле | Значение | Источник |
|------|----------|----------|
| Тип | type confusion, "improved checks" | Apple [5] |
| CWE | CWE-843 | NVD [1] |
| CVSS 3.1 | 8.8 HIGH, `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` | NVD [1] |
| Bugzilla | 267134 | Apple [5] |
| Фикс | Safari 17.3, iOS 15.8.7/16.7.5/17.3, macOS 12.7.3/13.6.4/14.3, tvOS 17.3, visionOS 1.0.2 | NVD [1] |
| Exploited | "may have been exploited", "associated with the Coruna exploit, shipped in iOS 17.3 on Jan 22, 2024" | NVD [1] |
| CISA KEV | added 2024-01-23, due 2024-02-13 | CISA [13] |
| Coruna chain | cassowary, iOS 16.6–17.2.1 | cside [11], Centripetal [12] |

## 3.2 Механика (cside)
1. Функция вызывается 1,000,000 раз с float-аргументами →
   JIT специализирует под float array (каждый элемент = double) [11]
2. После JIT: один элемент массива заменяется **JS object** вместо float [11]
3. JIT-код читает как float → **указатель объекта трактуется как 64-bit double** [11]
4. = **type confusion**: `JSObject*` treated as `double`
5. Чтение confused float → **addrof** (адрес объекта в JSC heap) [11]
6. Обратное: запись crafted float → **fakeobj** (указатель на память атакующего) [11]
7. addrof + fakeobj → **fake ArrayBuffer** с backing store на произвольный адрес
8. Чтение/запись через fake ArrayBuffer → **arbitrary process memory R/W** [11]
9. Стабилизация: heap spray 16-element float arrays + custom 64-bit int abstraction class [11]

## 3.3 Связь с нашим RCA (cassowary_harness.js)
- Наш harness: `tryGetConstantProperty` race (CFA vs Constant Folding),
  структура S1→S2→S3, watchpoint gap → type confusion [наш research]
- Coruna: float-array specialization → object-as-double → addrof/fakeobj
- Оба = type confusion в JSC DFG JIT; Coruna-описание = "что видит атакующий",
  наш harness = "как срабатывает race"

## 3.4 iOS-путь (NadSec)
- OfflineAudioContext heap corruption + SVG attribute manipulation [12]
- (альтернативный путь, не cassowary-DFG, но тот же класс)

## TODO
- [ ] Сверить: cassowary-DFG (наш harness) vs OfflineAudioContext (NadSec iOS) — один баг или два пути
- [ ] Bugzilla 267134: полный текст (нужен login)
