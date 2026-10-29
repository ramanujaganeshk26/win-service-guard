"""Win Service Guard: Windows Service and Startup Unquoted Path Security Auditor.

Audits Windows services and Startup registry entries for unquoted executable paths
containing whitespace (CWE-428 / Unquoted Service Path vulnerability), flags orphaned
binaries, and outputs remediation commands.
"""
import argparse
import json
import os
import re
import subprocess
import sys


def run_command(cmd):
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True, encoding="utf-8", errors="ignore")
        return res.stdout
    except Exception:
        return ""


def extract_binary_and_args(path_str):
    raw = path_str.strip()
    if not raw:
        return "", ""
    if raw.startswith('"'):
        end_quote = raw.find('"', 1)
        if end_quote != -1:
            return raw[1:end_quote], raw[end_quote + 1:].strip()
        return raw.strip('"'), ""
    parts = raw.split()
    for i in range(len(parts), 0, -1):
        candidate = " ".join(parts[:i])
        if os.path.exists(candidate) or candidate.lower().endswith((".exe", ".dll", ".sys", ".bat", ".cmd")):
            return candidate, " ".join(parts[i:])
    match = re.search(r"\.(exe|dll|sys|bat|cmd)", raw, flags=re.IGNORECASE)
    if match:
        end_idx = match.end()
        return raw[:end_idx].strip(), raw[end_idx:].strip()
    return raw, ""


def is_vulnerable(raw_path):
    raw = raw_path.strip()
    if raw.startswith('"') and raw.endswith('"'):
        return False
    binary, _ = extract_binary_and_args(raw)
    return " " in binary and not raw.startswith('"')


def quote_path(path_str):
    raw = path_str.strip()
    binary, args = extract_binary_and_args(raw)
    quoted_binary = f'"{binary}"' if " " in binary and not binary.startswith('"') else binary
    if not quoted_binary.startswith('"') and " " in raw:
        quoted_binary = f'"{binary}"'
    return f"{quoted_binary} {args}".strip() if args else quoted_binary


def audit_services(vulnerable_only=True):
    issues = []
    out = run_command(["sc", "queryex", "state=all", "type=service"])
    services = []
    for line in out.splitlines():
        if "SERVICE_NAME:" in line:
            services.append(line.split(":", 1)[1].strip())

    for svc in services:
        cfg_out = run_command(["sc", "qc", svc])
        path = ""
        for line in cfg_out.splitlines():
            if "BINARY_PATH_NAME" in line:
                path = line.split(":", 1)[1].strip()
                break
        if not path:
            continue
        vuln = is_vulnerable(path)
        if vuln or (not vulnerable_only and not path.startswith('"') and " " in path):
            binary, args = extract_binary_and_args(path)
            suggested = quote_path(path)
            issues.append({
                "type": "service",
                "name": svc,
                "raw_path": path,
                "binary": binary,
                "args": args,
                "vulnerable": vuln,
                "suggested": suggested,
            })
    return issues


def audit_startup_registry():
    issues = []
    keys = [
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    ]
    for key in keys:
        out = run_command(["reg", "query", key])
        for line in out.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) >= 3 and parts[1].upper() in ("REG_SZ", "REG_EXPAND_SZ"):
                name, val = parts[0], parts[2]
                if is_vulnerable(val):
                    binary, args = extract_binary_and_args(val)
                    issues.append({
                        "type": "startup_registry",
                        "name": f"{key}\\{name}",
                        "raw_path": val,
                        "binary": binary,
                        "args": args,
                        "vulnerable": True,
                        "suggested": quote_path(val),
                    })
    return issues


def generate_fix_script(issues, filepath):
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("@echo off\n:: Remediation script for unquoted service paths\n\n")
        for item in issues:
            if item["type"] == "service":
                fixed = item["suggested"].replace('"', '\\"')
                f.write(f'echo Fixing service: {item["name"]}\n')
                f.write(f'sc config "{item["name"]}" binPath= "{fixed}"\n')
    return os.path.abspath(filepath)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Windows Service & Startup Unquoted Path Security Auditor")
    parser.add_argument("--all", action="store_true", help="Include all unquoted service paths with arguments")
    parser.add_argument("--check", action="store_true", help="Exit status code 1 if unquoted path vulnerabilities exist")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--fix-script", help="Save safe batch remediation script to path")
    args = parser.parse_args(argv)

    svc_issues = audit_services(vulnerable_only=not args.all)
    reg_issues = audit_startup_registry()
    all_issues = svc_issues + reg_issues

    if args.json:
        print(json.dumps({"count": len(all_issues), "issues": all_issues}, indent=2))
    else:
        print("[*] Win Service Guard - Windows Unquoted Path Auditor")
        print(f"[*] Found {len(all_issues)} item(s) requiring attention.\n")
        for item in all_issues:
            tag = "[VULNERABLE (CWE-428)]" if item.get("vulnerable") else "[UNQUOTED ARGS]"
            print(f"{tag} {item['type'].upper()}: {item['name']}")
            print(f"  Current:   {item['raw_path']}")
            print(f"  Suggested: {item['suggested']}\n")

    if args.fix_script:
        out_path = generate_fix_script([i for i in all_issues if i["type"] == "service"], args.fix_script)
        if not args.json:
            print(f"[+] Remediation script written to: {out_path}")

    if args.check and any(i.get("vulnerable") for i in all_issues):
        sys.exit(1)


if __name__ == "__main__":
    main()
