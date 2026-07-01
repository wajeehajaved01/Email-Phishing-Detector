"""
keyword_analyzer.py
Scans email body for phishing keywords and suspicious URLs.
"""

import re


# ─── Phishing keyword database ───────────────────────────────────────────────
PHISHING_KEYWORDS = {
    # Account threats
    "your account has been suspended"  : "HIGH",
    "account will be closed"           : "HIGH",
    "verify your account"              : "HIGH",
    "confirm your identity"            : "MEDIUM",
    "unusual sign-in activity"         : "MEDIUM",
    "your password has expired"        : "MEDIUM",
    "update your billing"              : "MEDIUM",
    "payment information required"     : "MEDIUM",

    # Urgency / pressure
    "urgent action required"           : "HIGH",
    "act immediately"                  : "HIGH",
    "respond within 24 hours"          : "MEDIUM",
    "limited time offer"               : "LOW",
    "expires today"                    : "MEDIUM",
    "final notice"                     : "MEDIUM",
    "last warning"                     : "HIGH",

    # Financial lures
    "you have won"                     : "HIGH",
    "claim your prize"                 : "HIGH",
    "wire transfer"                    : "HIGH",
    "send money"                       : "HIGH",
    "gift card"                        : "HIGH",
    "inheritance funds"                : "HIGH",
    "lottery winner"                   : "HIGH",
    "unclaimed refund"                 : "MEDIUM",

    # Credential harvesting
    "click here to login"              : "HIGH",
    "click here to verify"             : "HIGH",
    "enter your credentials"           : "HIGH",
    "sign in to continue"              : "MEDIUM",
    "reset your password now"          : "MEDIUM",

    # Generic deception
    "dear customer"                    : "LOW",
    "dear valued member"               : "LOW",
    "congratulations you have been selected" : "HIGH",
}

# ─── URL suspicion patterns ──────────────────────────────────────────────────
SUSPICIOUS_URL_PATTERNS = [
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP address used instead of domain"),
    (r"https?://[^\s]*@",                              "Credentials embedded in URL"),
    (r"bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly",    "URL shortener used (hides destination)"),
    (r"[^\s]+-[^\s]+\.(tk|ml|ga|cf|gq|xyz|top|click|loan|win)", "High-risk TLD in URL"),
    (r"paypa[^l]|g00gle|amaz0n|micros0ft",             "Typosquatted domain in URL"),
    (r"https?://[^\s]*\.(exe|zip|bat|cmd|msi|vbs|ps1)", "Executable file linked"),
]


def scan_keywords(body: str) -> list[dict]:
    """
    Scan body text for phishing keywords.
    Returns list of {keyword, severity} dicts.
    """
    body_lower = body.lower()
    found = []
    for phrase, severity in PHISHING_KEYWORDS.items():
        if phrase in body_lower:
            found.append({"keyword": phrase, "severity": severity})
    return found


def scan_urls(body: str) -> list[dict]:
    """
    Extract URLs from body and flag suspicious ones.
    Returns list of {url, reason} dicts.
    """
    # Find all URLs in body
    urls = re.findall(r"https?://[^\s<>\"']+", body)
    flagged = []

    for url in urls:
        for pattern, reason in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                flagged.append({"url": url[:80], "reason": reason})
                break   # one flag per URL is enough

    return flagged
