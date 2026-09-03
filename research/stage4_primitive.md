# Stage 4 — Primitive (arbitrary R/W)

> **Вектор A: Coruna/cassowary (iOS 16.6–17.2.1, ИСТОРИЧЕСКИЙ)**
> Источники: cside [11], Centripetal [12].
> Примитив (R/W) **универсален** для обоих векторов.

## 4.1 addrof / fakeobj
- **addrof**: confused float read → адрес объекта в JSC heap [11]
- **fakeobj**: crafted float write → указатель на память атакующего [11]
- Комбинация → **fake ArrayBuffer** (backing store = произвольный адрес) [11]

## 4.2 Fake ArrayBuffer → arbitrary R/W
- Чтение/запись через fake ArrayBuffer = полный R/W процессной памяти [11]
- Стабилизация: heap spray (16-element float arrays) +
  custom 64-bit integer abstraction class [11]

## 4.3 Wasm-вариант (NadSec)
- **306-byte WebAssembly module** (inline в JS) компилируется,
  dispatch pointer hijacked → **native function call primitive** [12]
- Wasm sandbox → native call (альтернатива fake ArrayBuffer)

## 4.4 Offsets
- 41 JSC internal structure offset, 3 WebKit version thresholds [12]
- TODO: извлечь offset-таблицы (зависит от версии WebKit)

## TODO
- [ ] Offsets JSCell header (x86_64 vs arm64, iOS 26)
- [ ] Fake ArrayBuffer layout для целевой версии
