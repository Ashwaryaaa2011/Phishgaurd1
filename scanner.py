
import re
import ipaddress
from urllib.parse import urlsplit

# Words that can sometimes appear in phishing URLs
SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "account",
    "password",
    "update",
    "secure",
    "free",
    "banking",
    "signin"
]


def scan_url(url):

    score = 0
    findings = []

    # 1. Check URL format
    try:
        parsed = urlsplit(url.strip())

        if parsed.scheme not in ["http", "https"]:
            raise ValueError("Invalid scheme")

        hostname = parsed.hostname

        if not hostname:
            raise ValueError("Missing hostname")

        # Check for invalid port numbers
        parsed.port

    except ValueError:
        return {
            "valid": False,
            "score": 0,
            "risk": "Invalid URL",
            "findings": ["Please enter a valid HTTP or HTTPS URL."]
        }

    # 2. Check HTTPS
    if parsed.scheme != "https":
        score += 15
        findings.append("Website does not use HTTPS.")

    # 3. Check URL length
    if len(url) > 75:
        score += 10
        findings.append("URL is unusually long.")

    # 4. Check whether hostname is an IP address
    try:
        ipaddress.ip_address(hostname)
        score += 25
        findings.append("Website uses an IP address.")
    except ValueError:
        pass

    # 5. Check suspicious keywords
    found_words = [
        word for word in SUSPICIOUS_WORDS
        if word in url.lower()
    ]

    if found_words:
        score += min(len(found_words) * 5, 20)
        findings.append(
            "Suspicious words found: " + ", ".join(found_words)
        )

    # 6. Check @ symbol
    if "@" in url:
        score += 25
        findings.append("URL contains an @ symbol.")

    # 7. Check number of subdomains
    if len(hostname.split(".")) > 4:
        score += 15
        findings.append("URL contains many subdomains.")

    # Limit score to 100
    score = min(score, 100)

    # 8. Decide risk level
    if score >= 50:
        risk = "High Risk"
    elif score >= 20:
        risk = "Medium Risk"
    else:
        risk = "Low Risk"

    if not findings:
        findings.append(
            "No suspicious characteristics detected."
        )

    return {
        "valid": True,
        "score": score,
        "risk": risk,
        "findings": findings
    }
