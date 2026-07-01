"""
header_analyzer.py
Detects sender spoofing by comparing From, Reply-To,
Return-Path, Message-ID, and Received chain domains.
"""

import re


SUSPICIOUS_TLD = [".xyz", ".top", ".click", ".loan", ".win",
                  ".gq", ".ml", ".cf", ".tk", ".work"]

TYPOSQUAT_TARGETS = [
    "paypal", "google", "amazon", "microsoft", "apple",
    "netflix", "facebook", "instagram", "twitter", "bank",
    "ebay", "linkedin", "dropbox", "chase", "wellsfargo",
]


def _looks_like_typosquat(domain: str) -> str | None:
    """Check if domain uses typosquatting against known brands."""
    d = domain.lower().split(".")[0]          # e.g. paypa1, g00gle
    for brand in TYPOSQUAT_TARGETS:
        if d != brand and _similarity(d, brand) >= 0.75:
            return brand
    return None


def _similarity(a: str, b: str) -> float:
    """Simple character overlap ratio (Jaccard-like)."""
    if not a or not b:
        return 0.0
    set_a, set_b = set(a), set(b)
    return len(set_a & set_b) / len(set_a | set_b)


def check_spoofing(headers: dict) -> list[dict]:
    """
    Run spoofing/header-anomaly checks.
    Returns list of flag dicts: {check, detail, severity}
    """
    flags = []

    sender  = headers.get("sender_domain", "")
    reply   = headers.get("reply_domain", "")
    ret     = headers.get("return_domain", "")
    msgid   = headers.get("msgid_domain", "")
    subject = headers.get("subject", "").lower()
    received= headers.get("received", [])

    # 1. Reply-To mismatch
    if reply and reply != sender:
        flags.append({
            "check"   : "Reply-To Mismatch",
            "detail"  : f"From domain '{sender}' ≠ Reply-To domain '{reply}'",
            "severity": "HIGH",
        })

    # 2. Return-Path mismatch
    if ret and ret != sender:
        flags.append({
            "check"   : "Return-Path Mismatch",
            "detail"  : f"From domain '{sender}' ≠ Return-Path domain '{ret}'",
            "severity": "MEDIUM",
        })

    # 3. Message-ID domain mismatch
    if msgid and sender and msgid != sender:
        flags.append({
            "check"   : "Message-ID Domain Mismatch",
            "detail"  : f"Message-ID uses '{msgid}', sender uses '{sender}'",
            "severity": "MEDIUM",
        })

    # 4. Missing Message-ID
    if not headers.get("message_id"):
        flags.append({
            "check"   : "Missing Message-ID",
            "detail"  : "Legitimate mailers always set a Message-ID",
            "severity": "LOW",
        })

    # 5. Suspicious TLD
    for tld in SUSPICIOUS_TLD:
        if sender.endswith(tld):
            flags.append({
                "check"   : "Suspicious TLD",
                "detail"  : f"Sender domain uses high-risk TLD: {tld}",
                "severity": "HIGH",
            })
            break

    # 6. Typosquatting
    brand = _looks_like_typosquat(sender)
    if brand:
        flags.append({
            "check"   : "Typosquatting Detected",
            "detail"  : f"'{sender}' resembles brand '{brand}'",
            "severity": "HIGH",
        })

    # 7. Urgency in subject
    urgency_words = ["urgent", "immediately", "verify now", "account suspended",
                     "action required", "limited time", "expires today", "warning"]
    found_urg = [w for w in urgency_words if w in subject]
    if found_urg:
        flags.append({
            "check"   : "Urgency Language in Subject",
            "detail"  : f"Keywords: {', '.join(found_urg)}",
            "severity": "MEDIUM",
        })

    # 8. Missing Received headers (direct injection suspicion)
    if not received:
        flags.append({
            "check"   : "No Received Headers",
            "detail"  : "Email has no Received headers — possible direct injection",
            "severity": "MEDIUM",
        })

    return flags
