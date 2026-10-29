import subprocess
import xml.etree.ElementTree as ET
import os
import sys

def run_command(cmd):
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True, encoding="utf-8", errors="ignore")
        return res.stdout
    except Exception as e:
        return ""

def audit_services():
    issues = []
    out = run_command([r"sc", r"queryex", r"state=all", r"type=service"])
    services = []
    for line in out.splitlines():
        if r"SERVICE_NAME:" in line:
            services.append(line.split(":", 1)[1].strip())
    
    for svc in services:
        cfg_out = run_command([r"sc", r"qc", svc])
        path = ""
        for line in cfg_out.splitlines():
            if r"BINARY_PATH_NAME" in line:
                path = line.split(":", 1)[1].strip()
                break
        if path and not path.startswith('"') and not path.endswith('"') and " " in path:
            issues.append({"type": "service", "name": svc, "path": path})
    return issues

def audit_tasks():
    issues = []
    out = run_command([r"schtasks", r"/query", r"/fo", r"XML", r"/v"])
    if not out:
        return issues
    try:
        root = ET.fromstring(out)
        ns = {"t": root.tag.split("}")[0].strip("{")}
        for task in root.iter('{http://schemas.microsoft.com/windows/2004/02/mit/task}Task'):
            pass
    except Exception:
        pass
    return issues

def quote_path(path):
    clean = path.strip('"')
    parts = clean.split()
    for i in range(len(parts), 0, -1):
        candidate = " ".join(parts[:i])
        if os.path.exists(candidate):
            remainder = " ".join(parts[i:])
            if remainder:
                return f'"{candidate}" {remainder}'
            else:
                return f'"{candidate}"'
    return f'"{clean}"'

def main():
    print("Auditing Windows services for unquoted paths...")
    svc_issues = audit_services()
    print(f"Found {len(svc_issues)} unquoted service paths.")
    for item in svc_issues:
        print(f"  Service: {item['name']}")
        print(f"    Path: {item['path']}")
        print(f"    Suggested: {quote_path(item['path'])}")

if __name__ == r"__main__":
    main()
