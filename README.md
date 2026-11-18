# phishing-link-inspector
Python CLI security tool that inspects URLs for phishing indicators, obfuscated redirects, raw IP hosts, and invalid SSL/TLS certificate
# Suspicious Link & Phishing Inspector

A lightweight, command-line Python security tool designed to help users and Junior SOC Analysts safely inspect unfamiliar URLs for common phishing indicators and verify SSL/TLS certificate authenticity before opening links in a web browser.

## Everyday Problem Solved
Phishing emails and fraudulent messages often disguise malicious destinations behind deceptive subdomains, `@` URL-obfuscation tricks, raw IP addresses, or unencrypted connections. Instead of blindly clicking a suspicious link, this script performs passive static URL analysis and an active TLS handshake check to flag security risks safely from the terminal.

## Security Checks Performed
* **Protocol Encryption Check:** Flags unencrypted `http://` links lacking HTTPS transport security.
* **Raw IP Address Detection:** Uses regular expressions (`re`) to detect URLs pointing directly to IPv4 addresses rather than registered domain names.
* **Credential / `@` Obfuscation Detection:** Identifies `@` characters in URLs used to trick users into misreading the true destination host.
* **Subdomain & URL Shortener Analysis:** Flags excessive subdomain nesting and common link-shortening services (`bit.ly`, `tinyurl.com`, `t.co`) that mask final destinations.
* **Live SSL/TLS Certificate Verification:** Establishes a socket connection on port `443` to verify certificate validity, calculate days until expiration, and display the issuing Certificate Authority (CA).

## Project Structure
```text
phishing-link-inspector/
├── link_inspector.py       # Main Python URL and SSL inspection script
├── README.md               # Project documentation
└── screenshots/
    └── scan_demo.png       # Terminal output showing safe vs. high-risk URL checks
```

## Prerequisites
* **Python 3.8+** (Built entirely with Python standard libraries: `re`, `socket`, `ssl`, `datetime`, and `urllib.parse`).

## How to Run
1. Clone this repository:
   ```bash
   git clone https://github.com
   cd phishing-link-inspector
   ```
2. Run the inspector from your terminal:
   ```bash
   python link_inspector.py
   ```
3. Paste any URL when prompted to view the heuristic pattern analysis and SSL certificate report.

## Sample Output (Threat Detection)
```text
=== Suspicious Link & Phishing Inspector ===
Enter the URL to inspect: http://198.51.100

Analyzing: http://198.51.100
--------------------------------------------------
Target Hostname : secure-update.com
SSL/TLS Status  : SSL Verification Failed: [Errno 11001] getaddrinfo failed

[!] SECURITY WARNINGS DETECTED:
  - Unencrypted connection: URL does not use HTTPS.
  - High Risk: URL contains an '@' symbol used to obscure the real destination.

VERDICT: DO NOT TRUST / VERIFY SENDER BEFORE CLICKING.
```
