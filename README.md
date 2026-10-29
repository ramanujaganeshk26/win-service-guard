# Win Service Guard

A lightweight, zero-dependency Windows utility that audits Windows Services and Startup Registry entries for unquoted executable paths with whitespace (**CWE-428 / Unquoted Service Path Vulnerability**), generates safe quoting remediations, and exports findings to JSON or batch scripts.

## The Problem (CWE-428)

When a Windows service is registered with an unquoted executable path containing spaces (e.g. `C:\Program Files\Example Vendor\Service.exe`), Windows attempts to execute each segment separated by spaces before reaching the true target:
1. `C:\Program.exe`
2. `C:\Program Files\Example.exe`
3. `C:\Program Files\Example Vendor\Service.exe`

If an unprivileged user has write access to any parent directory, they can place a malicious binary that runs with elevated service privileges (often `NT AUTHORITY\SYSTEM`).

## Features

- **Fast Service Audit**: Queries all installed Windows services via Service Control Manager (`sc.exe`).
- **Startup Registry Inspection**: Scans `HKLM` and `HKCU` Run keys for unquoted binaries.
- **Accurate Path & Argument Disambiguation**: Correctly parses executable boundaries from trailing arguments (`-k`, `--service`).
- **Remediation Script Generator**: Creates ready-to-run batch files utilizing `sc config "<name>" binPath= ...`.
- **CI / Pipeline Mode**: Supports `--check` exit codes and `--json` structured reports.
- **Standalone Executable**: Build single-binary `win-service-guard.exe` with no Python runtime required.

## Installation & Usage

### 1. Run with Python (Standard Library)

```bash
# Run default audit (flags actual vulnerable unquoted paths)
python win_service_guard.py

# Include all services with unquoted paths containing arguments
python win_service_guard.py --all

# Output structured JSON
python win_service_guard.py --json

# Generate batch fix script
python win_service_guard.py --fix-script fix_services.bat

# CI check mode (exit code 1 if vulnerabilities exist)
python win_service_guard.py --check
```

### 2. Standalone Windows Executable (.exe)

Run `build_exe.bat` on Windows to produce a standalone executable in `dist\win-service-guard.exe`:

```cmd
build_exe.bat
```

Once built:

```cmd
dist\win-service-guard.exe --json
```

## Running Tests

```bash
python -m unittest test_win_service_guard.py
```

## License

MIT
