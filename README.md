# Automated Web Scanner

A Python command-line tool that audits a website for missing security headers, insecure cookies, information leaks and CORS misconfigurations.

**Created By:** Harishmitha M
---

## Project Description

Many web attacks (XSS, clickjacking, MIME sniffing, cross-origin data theft) can be reduced by sending the right HTTP response headers and configuring CORS correctly. This tool automates that audit: it sends HTTP requests to a target URL, inspects the responses, and prints a PASS / WARN / FAIL report. Results can also be saved as a JSON file.

## Features

- Checks 6 key security headers: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Detects information-leaking headers (`Server`, `X-Powered-By`, `X-AspNet-Version`)
- Checks whether the site is served over HTTPS
- Checks cookies for missing `Secure` and `HttpOnly` flags
- Tests CORS by sending fake `Origin` headers (`https://evil.com`, `null`) and detecting wildcard or reflected origins
- Prints a colour-free, readable report with a summary count
- Optional JSON report export

## Technologies Used

- Python 3.8+
- `requests` library
- Standard library: `argparse`, `json`, `datetime`, `sys`

## Dataset

No dataset is required. The tool works on live HTTP responses from the target website.

## Setup and Run Instructions

1. Clone the repository
   ```
   git clone https://github.com/<your-username>/<your-repo-name>.git
   cd <your-repo-name>
   ```
2. (Optional) Create a virtual environment
   ```
   python -m venv venv
   venv\Scripts\activate        # Windows
   source venv/bin/activate     # Linux / macOS
   ```
3. Install dependencies
   ```
   pip install -r requirements.txt
   ```
4. Run the scanner
   ```
   python Harishmitha_WebScanner.py https://example.com
   ```
5. Save the report as JSON (optional)
   ```
   python Harishmitha_WebScanner.py https://example.com --json report.json
   ```

## Sample Output

```
[+] PASS  HTTPS: Uses HTTPS
[-] FAIL  Content-Security-Policy: Missing. Mitigates XSS and data injection. Recommended: default-src 'self'
[+] PASS  Strict-Transport-Security: max-age=31536000
[!] WARN  Info leak: Server: nginx
[+] PASS  CORS (Origin: https://evil.com): Untrusted origin not allowed

Summary: PASS=3, FAIL=1, WARN=1
```

## Project Structure

```
.
├── Harishmitha_WebScanner.py      # main scanner script
├── requirements.txt               # dependencies
└── README.md                      # this file
```

## Legal and Ethical Notice

Only scan websites that you own or have written permission to test. This project is for educational purposes.
