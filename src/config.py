"""
Configuration and constants for Email Phishing Detector System
Centralizes all configuration to ensure consistency across modules
"""

import os
from enum import Enum
from typing import Set

# ============================================================================
# THREAT LEVELS
# ============================================================================

class ThreatLevel(Enum):
    """Email threat assessment levels"""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ============================================================================
# SUSPICIOUS INDICATORS
# ============================================================================

# High-risk Top-Level Domains often used in phishing
SUSPICIOUS_TLDS: Set[str] = {
    ".tk", ".ml", ".ga", ".cf",           # Free domains
    ".xyz", ".online", ".website",        # Generic extensions
    ".download", ".zip", ".trade",        # Suspicious purposes
    ".top", ".accountants", ".cricket",   # High-abuse TLDs
}

# Common phishing keywords in sender names
PHISHING_KEYWORDS: Set[str] = {
    "verify", "confirm", "validate", "urgent",
    "alert", "action required", "suspended", "locked",
    "update", "click here", "bank", "paypal", "amazon",
    "security", "billing", "payment", "refund",
}

# Known malicious domains (simulated - in production, this would be much larger)
KNOWN_MALICIOUS_DOMAINS: Set[str] = {
    "phishing-bank.com",
    "fake-amazon.net",
    "paypal-verify.org",
    "secure-login-verify.ru",
    "update-account-now.tk",
}

# Legitimate SPF/DKIM/DMARC indicators
LEGITIMATE_INDICATORS = {
    "spf_pass": 20,
    "dkim_pass": 20,
    "dmarc_pass": 20,
    "from_domain_match": 10,
}

# Red flags
RED_FLAGS = {
    "spf_fail": 30,
    "dkim_fail": 25,
    "dmarc_fail": 35,
    "header_injection": 40,
    "suspicious_url": 20,
    "malicious_attachment": 50,
}


# ============================================================================
# HEADER ANALYSIS CONFIGURATION
# ============================================================================

CRITICAL_HEADERS: Set[str] = {
    "From",
    "To",
    "Subject",
    "Date",
    "Message-ID",
    "MIME-Version",
    "Content-Type",
}

AUTHENTICATION_HEADERS: Set[str] = {
    "SPF-Result",
    "DKIM-Signature",
    "DMARC-Result",
    "Authentication-Results",
    "X-Original-Sender",
}

SPOOFING_INDICATORS: Set[str] = {
    "Reply-To",
    "Return-Path",
    "Sender",
}

# DNS timeout configuration
DNS_TIMEOUT_SECONDS = 5
DNS_RETRY_ATTEMPTS = 2


# ============================================================================
# URL ANALYSIS CONFIGURATION
# ============================================================================

# URL schemes that should raise alerts
SUSPICIOUS_URL_SCHEMES: Set[str] = {
    "data:",
    "javascript:",
    "vbscript:",
    "file:",
    "about:",
}

# Maximum URL length (to detect obfuscation)
MAX_NORMAL_URL_LENGTH = 500

# Common credential harvesting indicators in URLs
CREDENTIAL_HARVESTING_KEYWORDS: Set[str] = {
    "login", "signin", "verify", "confirm",
    "update", "validate", "authenticate", "secure",
    "account", "password", "credential",
}

# URL validation patterns
MIN_SAFE_HOSTNAME_LENGTH = 3
MAX_SAFE_HOSTNAME_LENGTH = 255


# ============================================================================
# ATTACHMENT ANALYSIS CONFIGURATION
# ============================================================================

# Maximum file size for analysis (10 MB)
MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024

# Dangerous file extensions
DANGEROUS_EXTENSIONS: Set[str] = {
    ".exe", ".bat", ".cmd", ".com", ".pif",
    ".scr", ".vbs", ".js", ".jar", ".zip",
    ".rar", ".7z", ".iso", ".dmg", ".pkg",
    ".app", ".bin", ".msi", ".dll", ".so",
}

# File signatures (magic numbers) - first few bytes
FILE_SIGNATURES = {
    "exe": b"MZ",
    "pdf": b"%PDF",
    "zip": b"PK\x03\x04",
    "rar": b"Rar!",
    "doc": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
}

# Maximum attachment count per email
MAX_ATTACHMENTS_PER_EMAIL = 50


# ============================================================================
# HASHING CONFIGURATION
# ============================================================================

# Use SHA-256 for all cryptographic hashing
HASH_ALGORITHM = "sha256"

# Block size for streaming hash calculation (1MB)
HASH_BLOCK_SIZE = 1024 * 1024


# ============================================================================
# THREAT INTELLIGENCE CONFIGURATION
# ============================================================================

# Simulated threat intelligence API endpoints
THREAT_INTEL_ENDPOINTS = {
    "virustotal": "https://www.virustotal.com/api/v3/files",
    "abuse_ipdb": "https://api.abuseipdb.com/api/v2/check",
    "urlhaus": "https://urlhaus-api.abuse.ch/v1/url/",
}

# Cache expiration time for threat intelligence (24 hours)
THREAT_INTEL_CACHE_EXPIRATION = 24 * 60 * 60


# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_LEVEL = "INFO"

# Log file location
LOGS_DIR = "logs"
LOG_FILE = os.path.join(LOGS_DIR, "phishing_detector.log")

# Maximum log file size (10 MB)
LOG_FILE_MAX_BYTES = 10 * 1024 * 1024
LOG_FILE_BACKUP_COUNT = 5


# ============================================================================
# REPORT CONFIGURATION
# ============================================================================

# Report output formats
REPORT_FORMATS = ["console", "json", "html", "pdf"]

# Detailed analysis report template sections
REPORT_SECTIONS = {
    "header_analysis": "Email Header Analysis",
    "url_analysis": "URL Analysis",
    "attachment_analysis": "Attachment Analysis",
    "risk_assessment": "Risk Assessment",
    "recommendations": "Recommendations",
}


# ============================================================================
# SCORING THRESHOLDS
# ============================================================================

# Threat score ranges (out of 100)
THREAT_SCORE_THRESHOLDS = {
    "SAFE": (0, 20),
    "LOW": (20, 40),
    "MEDIUM": (40, 60),
    "HIGH": (60, 80),
    "CRITICAL": (80, 100),
}

# Risk factors and their weights
RISK_WEIGHTS = {
    "authentication_failure": 0.35,  # SPF/DKIM/DMARC failures
    "suspicious_content": 0.25,      # URLs, keywords
    "attachment_risk": 0.25,         # File analysis
    "header_anomaly": 0.15,          # Structural issues
}


# ============================================================================
# RECOMMENDATIONS MAPPING
# ============================================================================

RECOMMENDATIONS = {
    "SAFE": [
        "This email appears legitimate.",
        "Standard email security checks passed.",
        "No suspicious indicators detected.",
    ],
    "LOW": [
        "Be cautious with links and attachments.",
        "Verify sender identity before responding.",
        "Check email authentication headers.",
    ],
    "MEDIUM": [
        "Do not click links or download attachments.",
        "Contact sender through alternative channel to verify.",
        "Report to IT security team.",
    ],
    "HIGH": [
        "Do NOT interact with this email.",
        "Delete immediately after reporting.",
        "Mark as spam/phishing.",
        "Contact IT security urgently.",
    ],
    "CRITICAL": [
        "CRITICAL PHISHING ALERT.",
        "Delete immediately without opening attachments.",
        "Report to email administrator.",
        "Consider account password reset.",
        "Monitor account for unauthorized activity.",
    ],
}


# ============================================================================
# ENVIRONMENT & PATHS
# ============================================================================

# Data directory paths
DATA_DIR = "data"
MALICIOUS_URLS_FILE = os.path.join(DATA_DIR, "malicious_urls.txt")
SUSPICIOUS_DOMAINS_FILE = os.path.join(DATA_DIR, "suspicious_domains.txt")
THREAT_INTEL_CACHE_FILE = os.path.join(DATA_DIR, "threat_intel_cache.json")

# Sample emails directory
SAMPLE_EMAILS_DIR = os.path.join(DATA_DIR, "sample_emails")

# Test data directory
TEST_DATA_DIR = "tests/fixtures"

# Reports directory
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)


# ============================================================================
# SECURITY CONSTRAINTS
# ============================================================================

# Input constraints
MAX_EMAIL_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_HEADER_LINE_LENGTH = 1000
MAX_FROM_ADDRESS_LENGTH = 320

# Processing constraints
MAX_URLS_TO_ANALYZE = 100
MAX_RECIPIENTS_TO_CHECK = 500

# Prevent DOS attacks
RATE_LIMIT_EMAILS_PER_MINUTE = 60
ANALYSIS_TIMEOUT_SECONDS = 30


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_threat_level(score: float) -> ThreatLevel:
    """
    Convert numeric threat score to ThreatLevel enum
    
    Args:
        score: Threat score (0-100)
    
    Returns:
        ThreatLevel enum value
    """
    if score < 20:
        return ThreatLevel.SAFE
    elif score < 40:
        return ThreatLevel.LOW
    elif score < 60:
        return ThreatLevel.MEDIUM
    elif score < 80:
        return ThreatLevel.HIGH
    else:
        return ThreatLevel.CRITICAL


def get_recommendations(threat_level: ThreatLevel) -> list:
    """Get safety recommendations based on threat level"""
    return RECOMMENDATIONS.get(threat_level.value, [])


if __name__ == "__main__":
    print("Configuration loaded successfully")
    print(f"Threat Levels: {[tl.value for tl in ThreatLevel]}")
    print(f"Suspicious TLDs: {len(SUSPICIOUS_TLDS)} domains")
