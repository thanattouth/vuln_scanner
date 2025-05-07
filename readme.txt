
==============================
 Web Vulnerability Scanner Tool
==============================

Author: thanattouth
Version: beta

This tool scans a target website for common vulnerabilities including SQL Injection (SQLi),
Reflected XSS, and DOM-based XSS. It supports both form-based and JWT-based authentication.

--------------------------------------------------
🛠️ Requirements:
--------------------------------------------------
- Python 3.8+
- Firefox browser (for DOM XSS via Selenium)
- Geckodriver installed and in PATH
- pip install -r requirements.txt

--------------------------------------------------
🚀 How to Run:
--------------------------------------------------
$ python scanner.py

You will be prompted for:
1. Target URL:             → e.g., https://example.com
2. Do you need login?      → y/n
3. Login type:             → form / jwt (auto-detected if unknown)
4. Login URL:              → e.g., https://example.com/login
5. Username:               → e.g., admin
6. Password:               → your password
7. JWT Field (if needed):  → e.g., access_token (auto-detected if blank)

--------------------------------------------------
🔍 What It Does:
--------------------------------------------------
- Crawls and extracts all forms from the target page.
- Submits a series of payloads to detect:
    ✔️ SQL Injection (error-based, simple bypasses)
    ✔️ Reflected XSS (alert-based)
    ✔️ DOM-based XSS (via headless Firefox)

- Stores results in a file named `scan_results.json`

--------------------------------------------------
📦 Output:
--------------------------------------------------
- scan_results.json → All found vulnerabilities in structured format

--------------------------------------------------
📌 Notes:
--------------------------------------------------
- The tool cannot detect CSRF-protected or JavaScript-only login flows.
- CAPTCHA and 2FA are not bypassed.
- Ensure geckodriver is installed and in system PATH for DOM XSS detection.

--------------------------------------------------
✅ Best Use Cases:
--------------------------------------------------
- TryHackMe / CTF challenge automation
- Quick vulnerability checks on dev/staging websites
- Learning input sanitization issues

--------------------------------------------------
🔒 Disclaimer:
--------------------------------------------------
This tool is intended for authorized testing only.
Unauthorized scanning of third-party websites may be illegal.
Use responsibly and ethically.

