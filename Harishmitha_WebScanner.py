#!/usr/bin/env python3
"""
Automated Web Scanner
Audits a website for missing secure headers and CORS misconfigurations.

Usage:
    python web_scanner.py https://example.com
    python web_scanner.py https://example.com --json report.json

Only scan sites you own or have written permission to test.
"""

import argparse
import json
import sys
from datetime import datetime

import requests

TIMEOUT = 10

# header -> (why it matters, recommended value)
SECURITY_HEADERS = {
    "Content-Security-Policy": ("Mitigates XSS and data injection", "default-src 'self'"),
    "Strict-Transport-Security": ("Forces HTTPS", "max-age=31536000; includeSubDomains"),
    "X-Frame-Options": ("Prevents clickjacking", "DENY or SAMEORIGIN"),
    "X-Content-Type-Options": ("Stops MIME-type sniffing", "nosniff"),
    "Referrer-Policy": ("Limits referrer data leakage", "strict-origin-when-cross-origin"),
    "Permissions-Policy": ("Restricts browser features", "geolocation=(), camera=()"),
}

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]


def check_headers(response):
    findings = []
    for header, (reason, recommended) in SECURITY_HEADERS.items():
        value = response.headers.get(header)
        if value:
            findings.append({"check": header, "status": "PASS", "detail": value})
        else:
            findings.append({
                "check": header,
                "status": "FAIL",
                "detail": f"Missing. {reason}. Recommended: {recommended}",
            })

    for header in LEAKY_HEADERS:
        value = response.headers.get(header)
        if value:
            findings.append({
                "check": f"Info leak: {header}",
                "status": "WARN",
                "detail": f"Exposes '{value}'. Consider hiding it.",
            })
    return findings


def check_https(url):
    if url.startswith("http://"):
        return [{"check": "HTTPS", "status": "FAIL", "detail": "Site is scanned over plain HTTP"}]
    return [{"check": "HTTPS", "status": "PASS", "detail": "Uses HTTPS"}]


def check_cookies(response):
    findings = []
    for cookie in response.cookies:
        issues = []
        if not cookie.secure:
            issues.append("no Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("no HttpOnly flag")
        if issues:
            findings.append({
                "check": f"Cookie: {cookie.name}",
                "status": "WARN",
                "detail": ", ".join(issues),
            })
    return findings


def check_cors(url):
    findings = []
    test_origins = ["https://evil.com", "null"]

    for origin in test_origins:
        try:
            r = requests.get(url, headers={"Origin": origin}, timeout=TIMEOUT)
        except requests.RequestException as e:
            findings.append({"check": "CORS", "status": "ERROR", "detail": str(e)})
            return findings

        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*":
            findings.append({
                "check": f"CORS (Origin: {origin})",
                "status": "WARN",
                "detail": "Wildcard (*) allows any site to read responses",
            })
        elif acao == origin:
            severity = "FAIL" if acac == "true" else "WARN"
            findings.append({
                "check": f"CORS (Origin: {origin})",
                "status": severity,
                "detail": "Reflects arbitrary Origin"
                + (" with credentials allowed (high risk)" if acac == "true" else ""),
            })
        else:
            findings.append({
                "check": f"CORS (Origin: {origin})",
                "status": "PASS",
                "detail": "Untrusted origin not allowed",
            })
    return findings


def scan(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print(f"\nScanning {url} ...\n")
    try:
        response = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException as e:
        print(f"Could not reach target: {e}")
        sys.exit(1)

    results = []
    results += check_https(response.url)
    results += check_headers(response)
    results += check_cookies(response)
    results += check_cors(response.url)

    return {
        "target": response.url,
        "status_code": response.status_code,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "findings": results,
    }


def print_report(report):
    icons = {"PASS": "[+]", "FAIL": "[-]", "WARN": "[!]", "ERROR": "[x]"}
    for f in report["findings"]:
        print(f"{icons.get(f['status'], '[?]')} {f['status']:<5} {f['check']}: {f['detail']}")

    counts = {}
    for f in report["findings"]:
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    print("\nSummary:", ", ".join(f"{k}={v}" for k, v in counts.items()))


def main():
    parser = argparse.ArgumentParser(description="Web security headers and CORS scanner")
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--json", metavar="FILE", help="Save report to a JSON file")
    args = parser.parse_args()

    report = scan(args.url)
    print_report(report)

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"Report saved to {args.json}")


if __name__ == "__main__":
    main()
