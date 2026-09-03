#!/bin/bash
# build_vulnerable_jsc.sh — собирает УЯЗВИМЫЙ jsc (Вектор A, CVE-2024-23222).
#
# Два пути:
#   Путь 1 (рекомендуемый): чистый checkout ДО патча (commit 77a6809 = parent of 6471469).
#   Путь 2: любой свежий checkout + revert_6471469.patch (возвращает уязвимость).
#
# Использование (macOS, Xcode):
#   ./build_vulnerable_jsc.sh            # Путь 1: checkout 77a6809
#   REVERT=1 ./build_vulnerable_jsc.sh   # Путь 2: revert патча на HEAD
#
# Результат: build/Release/jsc (уязвимый) -> прогоняем run_cassowary_harness.sh

set -euo pipefail
cd "$(dirname "$0")/.."

WEBKIT_DIR="${WEBKIT_DIR:-./WebKit}"
N="${N:-30}"

if [ "${REVERT:-0}" = "1" ]; then
    echo "=== Путь 2: revert патча 6471469 на текущем HEAD ==="
    git -C "$WEBKIT_DIR" apply --check patches/revert_6471469.patch \
        && git -C "$WEBKIT_DIR" apply patches/revert_6471469.patch \
        || { echo "revert не применился — нужен checkout, содержащий 6471469"; exit 1; }
    echo "revert применён: tryGetConstantProperty снова pre-patch"
else
    echo "=== Путь 1: checkout 77a6809 (parent of 6471469, pre-patch) ==="
    git -C "$WEBKIT_DIR" checkout 77a6809
fi

echo
echo "=== Сборка jsc (Release) ==="
# macOS:
#   cd "$WEBKIT_DIR"
#   ./Scripts/build-jsc --release
# (или Xcode: open Source/JavaScriptCore/JavaScriptCore.xcodeproj, target jsc, Release)
echo "Запустите: (cd $WEBKIT_DIR && ./Scripts/build-jsc --release)"
echo "ИЛИ Xcode: Source/JavaScriptCore/JavaScriptCore.xcodeproj -> jsc -> Release"

echo
echo "=== Проверка: прогон harness (ожидаем CRASH на уязвимом jsc) ==="
JSC="$WEBKIT_DIR/build/Release/jsc" N="$N" ./run_cassowary_harness.sh
