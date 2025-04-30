import time
import json
from urllib.parse import urljoin
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

SQLI_PAYLOADS = ["' OR '1'='1", "'; DROP TABLE users; --", "' OR 1=1--"]
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]

scanned_inputs = set()


def extract_forms(driver, url):
    driver.get(url)
    time.sleep(1)
    soup = BeautifulSoup(driver.page_source, "html.parser")
    forms = soup.find_all("form")
    form_details = []
    for form in forms:
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get").upper()
        inputs = [input.attrs.get("name") for input in form.find_all("input") if input.attrs.get("name")]
        form_details.append({"action": action, "method": method, "inputs": inputs})
    return form_details


def submit_form(driver, form, url, payloads, vulntype):
    action = form["action"]
    method = form["method"]
    inputs = form["inputs"]
    target = urljoin(url, action)
    findings = []

    for name in inputs:
        for payload in payloads:
            key = (target, name, method, vulntype, payload)
            if key in scanned_inputs:
                continue
            scanned_inputs.add(key)

            driver.get(target)
            time.sleep(1)
            try:
                input_elem = driver.find_element(By.NAME, name)
                input_elem.clear()
                input_elem.send_keys(payload)

                form_elem = driver.find_element(By.TAG_NAME, "form")
                if method == "POST":
                    driver.execute_script("arguments[0].submit();", form_elem)
                else:
                    form_elem.submit()
                time.sleep(1)

                if payload in driver.page_source:
                    risk = "High" if "DROP" in payload or "script" in payload else "Medium"
                    print(Fore.RED + f"[!] Possible {vulntype} detected via {method} in parameter: {name} [Risk: {risk}]")
                    findings.append({
                        "url": target,
                        "parameter": name,
                        "method": method,
                        "vulnerability": vulntype,
                        "payload": payload,
                        "risk": risk
                    })
            except Exception:
                continue
    return findings


def submit_react_form(driver, url, form_inputs, payloads, vulntype):
    findings = []
    for name in form_inputs:
        for payload in payloads:
            key = (url, name, "REACT-CLICK", vulntype, payload)
            if key in scanned_inputs:
                continue
            scanned_inputs.add(key)

            driver.get(url)
            time.sleep(1)

            try:
                input_elem = driver.find_element(By.NAME, name)
                input_elem.clear()
                input_elem.send_keys(payload)

                buttons = driver.find_elements(By.TAG_NAME, "button")
                for btn in buttons:
                    if any(keyword in btn.text.lower() for keyword in ["submit", "login", "send", "search"]):
                        btn.click()
                        time.sleep(1)

                        if payload in driver.page_source:
                            risk = "High" if "DROP" in payload or "script" in payload else "Medium"
                            print(Fore.RED + f"[!] Possible {vulntype} detected via React button in: {name} [Risk: {risk}]")
                            findings.append({
                                "url": url,
                                "parameter": name,
                                "method": "REACT-CLICK",
                                "vulnerability": vulntype,
                                "payload": payload,
                                "risk": risk
                            })
                        break
            except Exception:
                continue

    return findings


def main(target_url):
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    driver = webdriver.Chrome(options=options)

    findings = []
    print(Fore.CYAN + f"[~] Searching for forms in: {target_url}\n")
    forms = extract_forms(driver, target_url)

    if forms:
        print(Fore.GREEN + f"[+] Found {len(forms)} form(s)")
        for i, form in enumerate(forms):
            print(f"    Form #{i+1}: {form}")
            findings += submit_form(driver, form, target_url, SQLI_PAYLOADS, "SQL Injection")
            findings += submit_form(driver, form, target_url, XSS_PAYLOADS, "XSS")
    else:
        print(Fore.YELLOW + "[-] No traditional forms found. Trying React-based form scan...")
        react_inputs = ["username", "password"]  # This can be customized or detected dynamically
        findings += submit_react_form(driver, target_url, react_inputs, SQLI_PAYLOADS, "SQL Injection")
        findings += submit_react_form(driver, target_url, react_inputs, XSS_PAYLOADS, "XSS")

    driver.quit()

    if not findings:
        print(Fore.GREEN + "[✓] No vulnerabilities detected.")
    else:
        report_name = f"report_dynamic_{time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_name, "w") as f:
            json.dump(findings, f, indent=4)
        print(Fore.BLUE + f"[✓] Scan completed. Report saved to {report_name}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 scanner_dynamic.py <URL>")
        exit()
    main(sys.argv[1])
