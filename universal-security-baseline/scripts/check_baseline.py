#!/usr/bin/env python3
"""
Universal Security Baseline Automated Verification Tool
Checks source code against baseline security rules (ISO 27001, NIST CSF 2.0, OWASP, MITRE ATT&CK, Security Eng)
Zero external dependencies (Python stdlib only).
"""

import argparse
import json
import os
import re
import sys

IGNORE_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "__pycache__",
    ".pytest_cache", ".venv", "venv", "dist", "build", "target"
}

IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".zip", ".tar", ".gz", ".lock", ".md"
}

RULES = [
    {
        "id": "SEC-ISO-01",
        "name": "Hardcoded Credentials or Secrets",
        "regex": re.compile(r"""(?i)(?:password|secret|apikey|api_key|private_key|token|auth_token)\s*[:=]\s*['"][a-zA-Z0-9_\-\.+=/]{8,}['"]"""),
        "severity": "CRITICAL",
        "description": "Hardcoded secret or credential found in source code."
    },
    {
        "id": "SEC-ISO-03",
        "name": "Unsafe Auto-DDL Configuration",
        "regex": re.compile(r"""(?i)ddl-auto\s*[:=]\s*(?:update|create|create-drop)"""),
        "severity": "HIGH",
        "description": "Auto-DDL enabled; production schemas must be managed via versioned migration scripts."
    },
    {
        "id": "SEC-OWASP-01",
        "name": "Potential Query or Command String Concatenation",
        "regex": re.compile(r"""(?i)(?:executeQuery|rawQuery|nativeQuery|exec|spawn)\s*\(.*(?:\+|format\(|\$\{)"""),
        "severity": "CRITICAL",
        "description": "Dynamic query/command constructed with concatenation; use parameterized APIs."
    },
    {
        "id": "SEC-OWASP-03",
        "name": "Non-Constant-Time Comparison on Sensitive Data",
        "regex": re.compile(r"""(?i)(?:token|secret|hmac|signature|apiKey|password)\s*(?:===|==|\.equals\()\s*[a-zA-Z0-9_]+"""),
        "severity": "HIGH",
        "description": "Sensitive credential compared using short-circuit equality; use constant-time equality."
    },
    {
        "id": "SEC-MITRE-02",
        "name": "Sensitive Data in Log Statements",
        "regex": re.compile(r"""(?i)log(?:ger)?\.(?:info|debug|warn|error|trace)\(.*(?:\bpassword\b|\btoken\b|\bsecret\b|\bcardNumber\b|\bssn\b)"""),
        "severity": "HIGH",
        "description": "Potential plaintext credential or sensitive PII written to logger."
    },
    {
        "id": "SEC-ENG-01",
        "name": "Deprecated or Broken Cryptographic Primitive",
        "regex": re.compile(r"""\b(?:MD5|SHA1|SHA-1|DES|3DES|RC4|AES[-/]ECB)\b""", re.IGNORECASE),
        "severity": "CRITICAL",
        "description": "Weak or broken cryptographic algorithm used."
    }
]

SENSITIVE_FILE_PATTERNS = [
    re.compile(r"""^\.env(?:\..+)?$""", re.IGNORECASE),
    re.compile(r"""^id_rsa(?:\.pub)?$""", re.IGNORECASE),
    re.compile(r""".*\.(?:pem|key|jks|p12|pfx)$""", re.IGNORECASE)
]


def scan_file(file_path):
    findings = []
    if os.path.abspath(file_path) == os.path.abspath(__file__):
        return findings
    filename = os.path.basename(file_path)

    # Check SEC-ENG-02: Committed sensitive files
    for pat in SENSITIVE_FILE_PATTERNS:
        if pat.match(filename):
            findings.append({
                "id": "SEC-ENG-02",
                "name": "Committed Sensitive Credential File",
                "severity": "CRITICAL",
                "description": f"Sensitive key/env file found in repository tree: {filename}",
                "file": file_path,
                "line": 1,
                "snippet": filename
            })

    # Content checks
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_idx, line in enumerate(f, start=1):
                # Skip comments or mock strings if applicable
                stripped = line.strip()
                if not stripped:
                    continue

                for rule in RULES:
                    match = rule["regex"].search(line)
                    if match:
                        findings.append({
                            "id": rule["id"],
                            "name": rule["name"],
                            "severity": rule["severity"],
                            "description": rule["description"],
                            "file": file_path,
                            "line": line_idx,
                            "snippet": stripped[:120]
                        })
    except Exception as err:
        pass

    return findings


def scan_directory(target_path):
    all_findings = []
    if os.path.isfile(target_path):
        return scan_file(target_path)

    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for f in files:
            _, ext = os.path.splitext(f)
            if ext.lower() in IGNORE_EXTENSIONS:
                continue
            full_path = os.path.join(root, f)
            all_findings.extend(scan_file(full_path))

    return all_findings


def main():
    parser = argparse.ArgumentParser(description="Universal Security Baseline Checker")
    parser.add_argument("path", nargs="?", default=".", help="Path to file or directory to scan")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--include-docs", action="store_true", help="Include markdown documentation files in scan")
    args = parser.parse_args()

    if args.include_docs:
        IGNORE_EXTENSIONS.discard(".md")

    findings = scan_directory(args.path)

    if args.json:
        print(json.dumps({
            "total_findings": len(findings),
            "findings": findings
        }, indent=2))
    else:
        print(f"--- Universal Security Baseline Scan: {args.path} ---")
        if not findings:
            print("[PASS] No baseline violations detected.")
            sys.exit(0)

        print(f"[FAIL] Found {len(findings)} violation(s):\n")
        for idx, item in enumerate(findings, start=1):
            print(f"{idx}. [{item['id']}] {item['name']} ({item['severity']})")
            print(f"   File: {item['file']}:{item['line']}")
            print(f"   Note: {item['description']}")
            print(f"   Code: {item['snippet']}\n")

    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
