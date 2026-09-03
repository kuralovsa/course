#!/bin/bash
# run_cassowary_harness.sh — N попыток запуска cassowary_harness.js на
# уязвимом jsc. Race window узкий (~80% с slowdown в writeup), поэтому
# перезапускаем процесс. Crash (SIGSEGV) = баг сработал = теория подтверждена.
#
# Использование:
#   JSC=./build/Release/jsc N=20 ./run_cassowary_harness.sh
#   JSC=./build/Release/jsc N=20 EXTRA="--describe" ./run_cassowary_harness.sh
#
# JSC — путь к УЯЗВИМОЙ сборке jsc (WebKit до коммита 6471469, Safari < 17.3).
# Проверка патча: прогнать тот же harness на jsc >= 17.3 -> 0 crash'ей.

set -u
JSC="${JSC:-jsc}"
N="${N:-20}"
EXTRA="${EXTRA:-}"
LOGDIR="${LOGDIR:-/tmp/cassowary_logs}"
mkdir -p "$LOGDIR"

crashes=0
notriggered=0
other=0

for i in $(seq 1 "$N"); do
    timeout 180 "$JSC" cassowary_harness.js $EXTRA > "$LOGDIR/run_$i.log" 2>&1
    rc=$?
    if grep -q "BUG NOT TRIGGERED" "$LOGDIR/run_$i.log"; then
        echo "[$i/$N] no crash (race missed or patched) rc=$rc"
        notriggered=$((notriggered+1))
    elif [ "$rc" -ge 128 ] || [ "$rc" -eq 139 ] || [ "$rc" -eq 134 ]; then
        echo "[$i/$N] CRASH rc=$rc  (SIGSEGV/SIGABRT) -> bug fired"
        crashes=$((crashes+1))
    else
        echo "[$i/$N] rc=$rc (unexpected, see $LOGDIR/run_$i.log)"
        other=$((other+1))
    fi
done

echo
echo "=== RESULT: $crashes/$N crashes (bug fired), $notriggered no-crash, $other other ==="
if [ "$crashes" -gt 0 ]; then
    echo "ТЕОРИЯ ПОДТВЕРЖДЕНА: type confusion воспроизведена на уязвимом JSC"
else
    echo "баг не воспроизведён — проверить версию JSC (нужен < 17.3) и race"
fi
