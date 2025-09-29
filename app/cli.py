#!/usr/bin/env python3
"""
Unified CLI for Android App Security Scanner (Group-1)
Usage examples:
  python app/cli.py --apk tests/fixtures/sample.apk --out report.txt
  python app/cli.py --apk tests/fixtures/sample.apk --out report.pdf --run-frida --frida-script app/frida_scripts/activity_tracer.js --package com.example.app
"""
import argparse
import os
from app.static_analysis import analyze_apk
from app.report_writer import write_report
from app.frida_tools import run_frida_script

def parse_args():
    p = argparse.ArgumentParser(description="Android App Security Scanner (Group-1)")
    p.add_argument("--apk", "-a", help="Path to APK file", required=True)
    p.add_argument("--out", "-o", default="scan_report.txt", help="Output report path (txt or pdf)")
    p.add_argument("--run-frida", action="store_true", help="Run Frida dynamic scripts (device required)")
    p.add_argument("--frida-script", help="Path to frida script to run (JS)")
    p.add_argument("--package", help="Package name for dynamic checks (required for frida)")
    p.add_argument("--frida-timeout", type=int, default=30, help="Timeout seconds for frida runs")
    return p.parse_args()

def main():
    args = parse_args()
    apk_path = args.apk

    if not os.path.exists(apk_path):
        print(f"[!] APK not found: {apk_path}")
        raise SystemExit(2)

    # Static analysis
    print("[*] Running static analysis...")
    report = analyze_apk(apk_path)

    # Dynamic / Frida (optional)
    if args.run_frida:
        if not args.frida_script or not args.package:
            print("[!] To run frida you must provide --frida-script and --package")
        else:
            print(f"[*] Running Frida script {args.frida_script} against {args.package} (timeout={args.frida_timeout}s)")
            frida_findings = run_frida_script(args.package, args.frida_script, timeout=args.frida_timeout)
            report.setdefault("findings", []).extend(frida_findings)

    # Write report (text or pdf if supported)
    write_report(report, args.out)
    print(f"[+] Done. Report written to {args.out}")

if __name__ == "__main__":
    main()
