import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse


def check_url_patterns(url):
    """Analyzes a URL string for common phishing red flags."""
    warnings = []
    parsed = urlparse(url)

    # 1. Check if HTTPS is missing
    if parsed.scheme != "https":
        warnings.append("Unencrypted connection: URL does not use HTTPS.")

    hostname = parsed.hostname or ""

    # 2. Check if the hostname is a raw IP address instead of a domain name
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    if ip_pattern.match(hostname):
        warnings.append("High Risk: URL points directly to a raw IP address instead of a domain.")

    # 3. Check for '@' symbol trickery (browsers ignore everything before '@')
    if "@" in url:
        warnings.append("High Risk: URL contains an '@' symbol used to obscure the real destination.")

    # 4. Check for excessive subdomains (e.g., ://verify-account.com)
    if hostname.count(".") >= 4:
        warnings.append(f"Suspicious structure: Excessive subdomains detected ({hostname}).")

    # 5. Check for common URL shorteners that hide final destinations
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]
    if hostname.lower() in shorteners:
        warnings.append("Caution: URL shortener detected; final destination is hidden.")

    return hostname, warnings


def check_ssl_certificate(hostname):
    """Connects to port 443 to verify the domain's SSL/TLS certificate validity."""
    if not hostname:
        return False, "No valid hostname found."

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
                expiry_str = cert.get("notAfter")
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_date - datetime.utcnow()).days

                issuer_info = dict(x[0] for x in cert.get("issuer", []))
                issuer_name = issuer_info.get("organizationName", "Unknown Issuer")

                return True, f"Valid SSL Certificate | Issuer: {issuer_name} | Expires in {days_left} days"
    except Exception as error:
        return False, f"SSL Verification Failed: {error}"


def inspect_link():
    print("=== Suspicious Link & Phishing Inspector ===")
    raw_url = input("Enter the URL to inspect (e.g., https://arbeitsagentur.de): ").strip()

    if not raw_url.startswith(("http://", "https://")):
        raw_url = "http://" + raw_url

    print(f"\nAnalyzing: {raw_url}\n" + "-" * 50)

    hostname, warnings = check_url_patterns(raw_url)
    ssl_valid, ssl_message = check_ssl_certificate(hostname)

    print(f"Target Hostname : {hostname}")
    print(f"SSL/TLS Status  : {ssl_message}")

    if warnings:
        print("\n[!] SECURITY WARNINGS DETECTED:")
        for item in warnings:
            print(f"  - {item}")
    else:
        print("\n[+] Pattern Check Passed: No obvious URL structure red flags found.")

    if not ssl_valid or warnings:
        print("\nVERDICT: DO NOT TRUST / VERIFY SENDER BEFORE CLICKING.")
    else:
        print("\nVERDICT: APPEARS SAFE (Always verify sender context).")


if __name__ == "__main__":
    inspect_link()
