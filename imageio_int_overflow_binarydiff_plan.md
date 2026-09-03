# Binary-diff план ImageIO: iOS 26.6.0 vs 26.6.1

**Цель:** вытащить точное overflow-выражение (какое умножение, какие регистры, какая функция) + имя символа для lldb-брейкпоинта + подтвердить, патчится ли оно в 26.6.1 (если да — diff покажет сам фикс).

**Статус:** план, ждём IPSW обеих версий.

---

## 0. Исходные допущения

- **ImageIO лежит в dyld shared cache** (не отдельный dylib) → работаем с `System.dsc`, а не с `.dylib`.
- Нужны **IPSW обеих версий** (26.6.0 и 26.6.1) — из них вытаскиваем `System.dsc`.
- Архитектура: **arm64e** (PAC) — учитываем при дизассемблировании.
- Гипотеза из PoC: `size = (uint32_t)(width * height * SPS * (BPS/8))` в 32-bit арифметике. План — это **подтвердить/опровергнуть** и найти точное место.

---

## 1. Получение бинарников

```bash
# IPSW (ipsw.me / Apple). Извлекаем System.dsc из каждого.
ipsw extract iOS_26.6.0.ipsw   # -> System.dsc (26.6.0)
ipsw extract iOS_26.6.1.ipsw   # -> System.dsc (26.6.1)
# или просто: unzip iOS_26.6.0.ipsw System.dsc
```

---

## 2. Извлечение образа ImageIO из dsc

```bash
# 2.1 Найти ImageIO в dsc (load address + size)
dyld_info -arch arm64e System.dsc | grep -A6 "ImageIO"
# или
otool -arch arm64e -l System.dsc | grep -B2 -A12 "ImageIO"

# 2.2 Вытащить сам образ (dsc — плоский файл, образ лежит на своём load address)
# file_offset = image_load_addr - dsc_base
dd if=System.dsc bs=1 skip=$((LOAD_ADDR - DSC_BASE)) count=$SIZE of=imageio_26.6.0
# повторить для 26.6.1 -> imageio_26.6.1

# 2.3 (альтернатива, macOS 15+) — дамп dsc + dSYM
dyld_shared_cache_util dump System.dsc out.dsc
dsymutil -arch arm64e out.dsc        # символы/типы, если есть
```

> Если `dd`-каравинг кривит границы — используй `dsc_extractor` / `dyld_shared_cache_util` с выгрузкой конкретного образа; важны **полные `__TEXT` + `__DATA`** сегменты.

---

## 3. Поиск символов (ДО diff)

```bash
# 3.1 Символы ImageIO в dsc
nm out.dsc | grep -i "ImageIO" | head -50

# 3.2 TIFF-декодер — ищем точные entry points
nm out.dsc | grep -iE "tiff" | head -80
# кандидаты:
#   TIFFDecodeImage / TIFFDecodeImageBlock
#   TIFFReadProperties / TIFFGetField
#   TIFFComputeStripSize / TIFFComputeTileSize
#   TIFFGetBufferSize / TIFFStripSize
#   _TIFFDecodeStrip

# 3.3 Дизассемблер по конкретным функциям
objdump -d -M reg=numeric imageio_26.6.0 | \
  awk '/<TIFFDecodeImage>:/,/^$/' > tiffdecode_26.6.0.asm
```

> Если символы **stripped** (частично) — ищем по **импорту** (`otool -I`) и по **строкам** (`strings | grep -i tiff`), а затем по cross-reference в Ghidra/IDA.

---

## 4. Поиск паттерна умножения (в 26.6.0)

Ищем цепочку `width * height * SPS * (BPS/8)`, которая **тронкается до 32 бит** и уходит в `malloc`.

```bash
# 4.1 Все 32-bit умножения
grep -nE "mul w[0-9]+, w[0-9]+, w[0-9]+" imageio_26.6.0.asm | head -60

# 4.2 Ключевой паттерн: 2-3 подряд идущих mul / madd, результат -> malloc
#    ищем "mul ... ; mul ... ; bl _malloc" (или calloc / _malloc_zone_malloc)
grep -nE -A3 "mul w" imageio_26.6.0.asm | grep -B3 "bl.*malloc"

# 4.3 Маркеры overflow-check (если Apple уже частично чинил):
#    cmp + bcs/bhi после mul, либо 64-bit mul (mul x) + truncation (ubfx/uxth)
grep -nE -B2 "bcs|bhi|bcc" imageio_26.6.0.asm | grep -B2 "mul"
```

**Что считываем из дизассембли:**
- Какие регистры держат `width / height / SPS / BPS` (по аргументам функции / по `TIFFGetField`).
- Точная цепочка умножений и **где именно** результат приводится к 32 бит (`mul w` vs `mul x` + `ubfx #0,#32`).
- Уходит ли результат в `malloc` **до** проверки границ.

---

## 5. Binary diff (26.6.0 vs 26.6.1)

```bash
# 5.1 Function-level diff (radare2)
radiff2 imageio_26.6.0 imageio_26.6.1
# -> список изменённых функций; фокус на TIFF-декодере из шага 3

# 5.2 Точечный diff дизассембли по TIFF-функциям
diff <(objdump -d imageio_26.6.0  | awk '/<TIFFDecodeImage>:/,/^$/' ) \
     <(objdump -d imageio_26.6.1  | awk '/<TIFFDecodeImage>:/,/^$/' ) \
  | grep -nE "^[<>].*(mul|cmp|bcs|bhi|bl.*malloc|ubfx)"
```

**Как выглядит фикс overflow (что ищем в diff):**

| Признак фикса | Что значит |
|---|---|
| Добавлен `cmp` + `bcs/bhi` **до** `malloc` | overflow-check: `if (w > MAX/h) return err` |
| `mul w` → `mul x` (64-bit) + явная проверка | пересчёт в 64 бит |
| Клейм/валидация `width`/`height` на входе | bounds на header-поля |
| Новый вызов хелпера `TIFFCheckSize`/`ValidateDims` | вынесенная валидация |

> Если diff по TIFF-декодеру **пустой** → либо баг не в ImageIO, либо фикс в другом модуле (WebCore/WebKit) → расширяем поиск на `WebKit`/`CoreGraphics` в dsc.

---

## 6. Извлечение точного выражения

По дизассембли уязвимой функции (26.6.0) фиксируем:

```
функция   : <имя символа из шага 3>   (offset 0x... в ImageIO)
аргументы : x0=width, x1=height, x2=SPS, x3=BPS   (подтвердить по TIFFGetField)
выражение : size = (uint32_t)( width * height * SPS * (BPS/8) )
malloc    : _malloc(size)  на offset 0x...
write     : memcpy/decode -> buffer, len = width*height*SPS*(BPS/8)  (64-bit)
```

Это и есть **точное overflow-выражение + символ**, которые мы вставляем в PoC.

---

## 7. Верификация (lldb)

```bash
# На jailbroken iOS 26.6.0 (или macOS 26.x с тем же ImageIO)
lldb -- ./harness            # harness = CGImageSourceCreateImageAtIndex(payload)
(lldb) breakpoint set -n TIFFDecodeImage        # символ из шага 3
(lldb) run
# в точке умножения:
(lldb) register read x0 x1 x2 x3
(lldb) p (uint32_t)(x0 * x1 * x2 * (x3/8))     # 32-bit
(lldb) p (uint64_t)(x0 * x1 * x2 * (x3/8))     # 64-bit
# если 32-bit << 64-bit и malloc получил 32-bit -> overflow подтверждён
```

A/B: payload (краш) vs control (нет краша) — как в нашем crash oracle.

---

## 8. Сверка с Apple advisory — ВЕРИФИЦИРОВАНО (17 Aug 2026)

**Advisory:** [iOS 26.6.1 / iPadOS 26.6.1](https://support.apple.com/en-us/148282), Released August 17, 2026.
**Индекс:** [Apple security releases](https://support.apple.com/en-us/100100).

### 8.1 Точный компонент — ImageIO, integer overflow (RCE)

| Поле | Значение |
|---|---|
| **CVE** | **CVE-2026-65346** |
| **Компонент** | **ImageIO** |
| **Impact** | Processing an image may lead to **arbitrary code execution** |
| **Description** | An **integer overflow** was addressed with improved input validation |
| **Researcher** | Meta Red Team X — Nik Tsytsarkin |
| **Released** | 17 Aug 2026 |

> **Подтверждено:** баг класс = integer overflow в ImageIO, эффект = RCE. Это ровно наш PoC-сценарий (`size = (uint32_t)(w*h*SPS*(BPS/8))`). Компонент в advisory = **ImageIO** → фикс должен быть в ImageIO (или в его caller'е). Если diff по TIFF-декодеру пустой — см. §10 (фолбэк CG/демоны/WebKit).

### 8.2 Смежные ImageIO-строки в том же advisory

| CVE | Компонент | Impact | Description | Researcher |
|---|---|---|---|---|
| **CVE-2026-65347** | ImageIO | denial-of-service | improved checks | Geonha Lee (@leegn4a) |
| **CVE-2026-65346** | ImageIO | **arbitrary code execution** | **integer overflow**, improved input validation | Meta Red Team X — Nik Tsytsarkin |

> Две отдельные ImageIO-уязвимости в одном релизе: одна DoS (65347), одна RCE-integer-overflow (65346). Наша цель — **65346**.

### 8.3 Полный список CVE в iOS 26.6.1 (для контекста)

| Компонент | CVE | Impact |
|---|---|---|
| Audio | CVE-2026-65339 | leak sensitive user info (logic issue) |
| **ImageIO** | **CVE-2026-65347** | DoS |
| **ImageIO** | **CVE-2026-65346** | **RCE (integer overflow)** ← наша цель |
| IOGPUFamily | CVE-2026-64788 | memory corruption (web content) |
| Kernel | CVE-2026-65343 | UAF → unexpected termination (remote) |
| Kernel | CVE-2026-65349 | OOB read → read kernel memory |
| Kernel | CVE-2026-65330 | corrupt kernel memory |
| Telephony | CVE-2026-65329 | bypass IPSec auth |
| WebKit | CVE-2026-64784, 43795, 65338, 65341, 64782, 64781, 65351, 65340, 65337, 65336, 65335, 65333, 65332, 65331, 64715, 64780, 65334, 43794, 64787 | Safari crash / memory corruption |
| WebKit History | CVE-2026-64778 | leak sensitive data |
| WebKit Storage | CVE-2026-64779 | Safari crash |

> **Важно:** в advisory **нет** отдельной строки «Messages»/«iMessage» — значит iMessage-демоны в 26.6.1 не патчились. Это **снижает приоритет** фолбэка на IMTranscoderAgent/imagent (§10.3) и **повышает** приоритет CoreGraphics (§10.2) как caller'а ImageIO.

### 8.4 Вывод для плана

1. **Компонент = ImageIO** (подтверждено) → основной diff (§1–7) по ImageIO — правильный.
2. **Bug class = integer overflow** (подтверждено) → ищем `mul w` + truncation + `malloc` (§4).
3. **Эффект = RCE** (подтверждено) → overflow даёт OOB write, не просто DoS.
4. **Нет iMessage-строки** → фолбэк-приоритет: CG (1) > WebKit (2) > демоны (3).
5. **Researcher = Meta Red Team X** → слот под публичный writeup: §8.5 (заполнить после получения URL/текста).


### 8.5 Публичный writeup CVE-2026-65346 (Meta Red Team X) — СЛОТ

> ⚠️ **Заготовка:** публичный writeup пока не получен/не верифицирован. До получения URL/текста точные функция/оффсеты **не вписывать как факт** — только в этот слот.

| Поле | Значение |
|---|---|
| **Источник** | TODO: URL writeup (Meta Red Team X / blog / GitHub / X) |
| **Функция (символ)** | TODO: e.g. `TIFFDecodeImage`, `TIFFComputeStripSize`, `TIFFGetBufferSize`, `CGBitmapContextCreate` |
| **Оффсет в ImageIO** | TODO: `imageio_base + 0x...` (arm64e, iOS 26.6.0) |
| **Точка умножения** | TODO: `mul wN, wM, wK` @ `imageio_base + 0x...` |
| **Точка аллокации** | TODO: `bl _malloc` / `bl _malloc_zone_malloc` / `CFAllocator` @ offset |
| **Overflow-выражение** | TODO: `size = (uint32_t)(width * height * SPS * (BPS/8))` или уточнённое |
| **Фикс в 26.6.1** | TODO: добавленный `cmp`/`bcs`/early-return, переход на `mul x`, константа-лимит |
| **Crash oracle** | TODO: lldb-брейкпоинт + payload/control из `imageio_int_overflow_crash_oracle.md` |
| **Уверенность** | низкая (writeup не получен) |

**Как заполнить слот:**
1. Найти публичный writeup по `CVE-2026-65346` / `Meta Red Team X` / `Nik Tsytsarkin`.
2. Вписать только подтверждённые значения (функция, offset, instruction, fix).
3. Если writeup даёт relative offset — сохранить привязку к `imageio_base` и архитектуре arm64e.
4. Сверить с binary diff (§5) и lldb-верификацией (§7).
5. После подтверждения перенести значения в §9 / `imageio_int_overflow_research.md` и снять TODO.

## 9. Аутпут и вписка в PoC

| Артефакт | Куда |
|---|---|
| Точное выражение + символ + offset | `imageio_int_overflow_research.md` §7 (снять TODO) |
| lldb-брейкпоинт (символ) | `imageio_int_overflow_crash_oracle.md` Run 2 |
| Подтверждённые dims (если выражение не `w*h*sps*bps/8`) | перегенерировать `imageio_int_overflow_poc.py` |
| Статус «патчится в 26.6.1 / нет» | README + research |

---

## Порядок работ (чек-лист)

1. [ ] IPSW 26.6.0 + 26.6.1 → `System.dsc`
2. [ ] Извлечь `imageio_26.6.0` / `imageio_26.6.1`
3. [ ] `nm` → символы TIFF-декодера
4. [ ] Дизассембли → найти цепочку `mul` + `malloc`
5. [ ] `radiff2` → изменившиеся функции (фикс?)
6. [ ] Зафиксировать выражение + символ + offset
7. [ ] lldb-верификация (32 vs 64 bit)
8. [ ] Сверка с Apple advisory (CVE/HT)
9. [ ] Заполнить §8.5 (writeup) или пометить «нет публичного writeup»
10. [ ] Вписать в PoC + research + oracle, пуш в репо

---

---

## 10. Фолбэк: CoreGraphics / iMessage-демоны / WebKit (если diff по ImageIO пустой)

**Логика:** пустой diff по TIFF-декодеру = фикс **не в самом умножении**. Overflow-выражение `w*h*SPS*(BPS/8)` вычисляется в ImageIO, но **аллокация буфера** и **bounds-check** часто живут в другом модуле. Apple чинит integer overflow не там, где умножение, а там, где по нему принимают решение (malloc / bounds).

**Шаг 0 (самый быстрый дизамбигуатор):** компонент в Apple security advisory для iOS 26.6.1 назван явно (`ImageIO` / `CoreGraphics` / `WebKit` / `Messages`). Это снимает 2 из 3 вариантов за одну секунду:
- `ImageIO`, а diff пустой → фикс в зависимом модуле (CG) или в caller'е (демон);
- `CoreGraphics` → сразу в CG;
- `Messages` → в демонах;
- `WebKit` → только если путь через WKWebView.

### 10.1 Приоритет (по убыванию вероятности для чистого TIFF-overflow)

| # | Модуль | Почему именно он | Где искать |
|---|--------|------------------|------------|
| **1** | **CoreGraphics** | ImageIO считает `size`, но **CG аллоцирует** буфер (`CGBitmapContextCreate` / `CGImageCreate`). Классическое место фикса: `if (w*h*bpp > MAX) return NULL` — на стороне аллокации, а не умножения | **dsc** |
| **2** | **iMessage-демоны** (`IMTranscoderAgent`, `imagent`) | Zero-click путь (Вектор Б) идёт через **IMTranscoderAgent** для транскодинга вложений. Демон может **сам** вычислять size с attacker-controlled dims **до** вызова ImageIO → фикс в caller'е | **НЕ в dsc** — отдельные Mach-O из `Root.fs` IPSW |
| **3** | **WebKit** | Только если контент = **link preview / rich card** в WKWebView. `WebCore::ImageDecoder` имеет свою валидацию size и свой путь аллокации, минуя наш TIFF-путь | **dsc** |

> Частая ошибка: ищешь демоны в dsc — их там **нет**. Они — отдельные Mach-O бинарники в `Root.fs`.

### 10.2 CoreGraphics (dsc)

```bash
# 10.2.1 Извлечь CG из того же System.dsc (26.6.0 / 26.6.1)
dyld_info -arch arm64e System.dsc | grep -A6 "CoreGraphics"
dd if=System.dsc bs=1 skip=$((CG_LOAD - DSC_BASE)) count=$CG_SIZE of=cg_26.6.0
# повторить для 26.6.1 -> cg_26.6.1

# 10.2.2 Символы аллокации bitmap-контекста
nm cg_26.6.0 | grep -iE "CGBitmapContext|CGImageCreate" | head -40
# кандидаты:
#   CGBitmapContextCreate / CGBitmapContextCreateWithData
#   CGBitmapContextGetData / CGBitmapContextBytesPerRow
#   CGImageCreate / CGImageCreateWithDataProvider

# 10.2.3 Diff
radiff2 cg_26.6.0 cg_26.6.1
diff <(objdump -d cg_26.6.0 | awk '/<CGBitmapContextCreate>:/,/^$/') \
     <(objdump -d cg_26.6.1 | awk '/<CGBitmapContextCreate>:/,/^$/') \
  | grep -nE "^[<>].*(cmp|bcs|bhi|bl.*malloc|mov.*#0x|cbz)"
```

**Что ищем в diff:** новый `cmp` + `bcs/bhi` **до** `malloc`, либо early-return «size too large» (константа-предел, `cbz` на результат проверки).

### 10.3 iMessage-демоны (из Root.fs IPSW, НЕ dsc)

```bash
# 10.3.1 Извлечь демоны из IPSW (отдельные Mach-O)
unzip iOS_26.6.0.ipsw -d ipsw_26.6.0
unzip iOS_26.6.1.ipsw -d ipsw_26.6.1
# пути (подтвердить find'ом, имена могут отличаться):
find ipsw_26.6.0/Root.fs -name "imagent" -o -name "*IMTranscoderAgent*"
#   Root.fs/usr/libexec/imagent
#   Root.fs/usr/libexec/com.apple.IMTranscoderAgent

cp ipsw_26.6.0/Root.fs/usr/libexec/imagent imagent_26.6.0
cp ipsw_26.6.1/Root.fs/usr/libexec/imagent imagent_26.6.1
# аналогично IMTranscoderAgent -> imta_26.6.0 / imta_26.6.1

# 10.3.2 Diff
radiff2 imagent_26.6.0 imagent_26.6.1
radiff2 imta_26.6.0 imta_26.6.1

# 10.3.3 Фокус: transcode/re-encode путь, где dims из header уходят в alloc
nm imta_26.6.0 | grep -iE "transcode|TIFF|decode|CGImage" | head -40
objdump -d imta_26.6.0 | grep -nE -A3 "mul w" | grep -B3 "bl.*malloc"
```

**Фокус:** функция, которая читает `width/height` из TIFF-header вложения и **до** вызова ImageIO вычисляет размер буфера. Если там появился `cmp`/bounds — фикс в caller'е.

### 10.4 WebKit (dsc)

```bash
# 10.4.1 Извлечь WebKit (большой образ, ~1GB — выделить место)
dyld_info -arch arm64e System.dsc | grep -A6 "WebKit"
dd if=System.dsc bs=1 skip=$((WK_LOAD - DSC_BASE)) count=$WK_SIZE of=webkit_26.6.0
# повторить для 26.6.1

# 10.4.2 Символы image-decoding
nm webkit_26.6.0 | grep -iE "WebCore::Image|ImageDecoder|ImageFrameLoader" | head -40

# 10.4.3 Diff (только если advisory = WebKit ИЛИ контент = link preview)
radiff2 webkit_26.6.0 webkit_26.6.1
diff <(objdump -d webkit_26.6.0 | awk '/<ImageDecoder>:/,/^$/') \
     <(objdump -d webkit_26.6.1 | awk '/<ImageDecoder>:/,/^$/') \
  | grep -nE "^[<>].*(cmp|bcs|bhi|bl.*malloc)"
```

### 10.5 Как подтвердить, что нашли правильный модуль

1. **A/B по crash oracle** (как в `imageio_int_overflow_crash_oracle.md`): payload (краш) vs control (нет) — но брейкпоинт ставим в **CG/демон**, а не в ImageIO.
2. **Call chain в lldb** на краше: кто **вызвал** ImageIO и кто **аллоцировал** буфер.
   - аллокация в CG с уже переполненным `size` → фикс в CG;
   - dims уже кривые на входе в ImageIO → фикс в caller'е (демон).
3. **Сверка с advisory:** компонент в Apple advisory должен совпасть с модулем, где найден diff.

### 10.6 Чек-лист фолбэка

1. [ ] Компонент из Apple advisory (HT-номер 26.6.1)
2. [ ] Если advisory = ImageIO, diff пустой → CoreGraphics (10.2)
3. [ ] Если не CG → IMTranscoderAgent / imagent (10.3, из Root.fs!)
4. [ ] WebKit (10.4) — только при подтверждённом link-preview-путь
5. [ ] lldb backtrace на краше: кто аллоцировал, кто вызвал
6. [ ] Вписать найденный модуль + фикс в `imageio_int_overflow_research.md`

---

**Честно:** без самих IPSW / dsc точные оффсеты и имя символа не вытащить — это требует бинарников обеих версий. План самодостаточен: как только будут `System.dsc` для 26.6.0 и 26.6.1, шаги 1–9 дают точное выражение и символ.
