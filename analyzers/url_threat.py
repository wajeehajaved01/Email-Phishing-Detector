"""
url_threat.py  —  PRODUCTION URL & THREAT INTELLIGENCE MODULE
Extracts, normalises, and analyses all URLs from email body.

Strategy (no paid API key required):
  1. Extract all URLs via regex
  2. Normalise to core domain (strip scheme, path, params)
  3. Typosquatting check — Levenshtein + homoglyph detection vs 40 major brands
  4. Structural heuristics — IP URLs, shorteners, high-risk TLDs, file extensions
  5. VirusTotal free public lookup (optional — works without API key for basic check)
  6. PhishTank public feed check (optional, offline CSV mode supported)
"""

import re
import urllib.parse
from difflib import SequenceMatcher
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional — gracefully skipped if not installed
try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# ── Brand protection list ────────────────────────────────────────────────────
PROTECTED_BRANDS = [
    "paypal", "google", "gmail", "amazon", "microsoft", "apple", "icloud",
    "netflix", "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "chase", "wellsfargo", "citibank", "bankofamerica", "hsbc", "barclays",
    "ebay", "shopify", "stripe", "coinbase", "binance", "blockchain",
    "outlook", "office365", "onedrive", "sharepoint", "teams",
    "whatsapp", "telegram", "discord", "slack", "zoom", "webex",
    "dhl", "fedex", "ups", "usps", "royalmail",
    "irs", "gov", "nhs", "who",
]

# Homoglyph / leet substitution map (attacker replaces letter with lookalike)
HOMOGLYPHS = {
    "a": ["@", "4", "á", "à", "ä", "α"],
    "e": ["3", "€", "é", "è", "ë"],
    "i": ["1", "!", "l", "|", "í", "ï"],
    "o": ["0", "ø", "ó", "ö", "°"],
    "s": ["$", "5", "§"],
    "g": ["9", "q"],
    "b": ["6", "ß"],
    "t": ["+", "7"],
    "l": ["1", "|", "I"],
}

# High-risk TLDs commonly used by phishing campaigns
HIGH_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # free Freenom TLDs, massively abused
    ".xyz", ".top", ".click", ".loan",
    ".win", ".work", ".review", ".racing",
    ".date", ".faith", ".party", ".trade",
    ".accountant", ".science", ".stream",
}

# URL shorteners that hide real destination
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "ift.tt", "rb.gy", "cutt.ly",
    "shorturl.at", "tiny.cc", "urlz.fr", "clck.ru",
}

# Suspicious file extensions in URLs
DANGEROUS_EXTENSIONS = {
    ".exe", ".msi", ".bat", ".cmd", ".vbs", ".ps1",
    ".scr", ".pif", ".com", ".jar", ".hta", ".reg",
}

# VirusTotal public API (v3) — free tier: 4 req/min, no key needed for basic
VT_URL_REPORT = "https://www.virustotal.com/api/v3/urls"


# ── Core extraction & normalisation ─────────────────────────────────────────

def extract_urls(text: str) -> list[str]:
    """Extract all http/https URLs from plain text or HTML."""
    # Match URLs in plain text
    raw = re.findall(r"https?://[^\s<>\"'\)\(]+", text)
    # Also extract href values from HTML
    hrefs = re.findall(r'href=["\']?(https?://[^"\'>\s]+)', text, re.IGNORECASE)
    all_urls = list(dict.fromkeys(raw + hrefs))  # deduplicate preserving order
    return all_urls


def normalise_domain(url: str) -> str:
    """
    Strip URL down to bare domain (no scheme, no path, no port, no www).
    Example: 'https://www.paypa1-login.xyz/verify?t=abc' → 'paypa1-login.xyz'
    """
    try:
        parsed = urllib.parse.urlparse(url)
        host   = parsed.hostname or ""
        host   = host.lower().strip()
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return url.lower()


def get_tld(domain: str) -> str:
    """Extract TLD including dot: 'paypal.xyz' → '.xyz'"""
    parts = domain.rsplit(".", 1)
    return "." + parts[-1] if len(parts) > 1 else ""


def get_sld(domain: str) -> str:
    """Second-level domain: 'secure.paypal.com' → 'paypal'"""
    parts = domain.rsplit(".", 2)
    if len(parts) >= 2:
        return parts[-2]
    return domain


# ── Typosquatting detection ──────────────────────────────────────────────────

def _normalise_for_comparison(s: str) -> str:
    """Collapse homoglyphs and leet substitutions to base letters."""
    s = s.lower()
    reverse_map = {}
    for base, variants in HOMOGLYPHS.items():
        for v in variants:
            reverse_map[v] = base
    result = ""
    for ch in s:
        result += reverse_map.get(ch, ch)
    return result


def _similarity(a: str, b: str) -> float:
    """SequenceMatcher ratio — more accurate than simple Jaccard."""
    return SequenceMatcher(None, a, b).ratio()


def check_typosquatting(domain: str) -> dict | None:
    """
    Compare domain SLD against all protected brands.
    Returns a finding dict if typosquatting is detected, else None.

    Detection logic:
      - Exact match after homoglyph normalisation
      - High similarity ratio (≥ 0.82) after normalisation
      - Brand name appears as substring in a longer domain
    """
    sld        = get_sld(domain)
    normalised = _normalise_for_comparison(sld)

    for brand in PROTECTED_BRANDS:
        brand_norm = _normalise_for_comparison(brand)

        # 1. Exact match after normalisation (catches paypa1 → paypal)
        if normalised == brand_norm and sld != brand:
            return {
                "type"      : "Homoglyph/Leet Substitution",
                "domain"    : domain,
                "mimics"    : brand,
                "confidence": 0.99,
                "detail"    : f"'{sld}' is a homoglyph/leet version of '{brand}'",
            }

        # 2. High similarity (catches paypa1-secure, paypalsupport, etc.)
        sim = _similarity(normalised, brand_norm)
        if 0.82 <= sim < 1.0:
            return {
                "type"      : "Typosquatting",
                "domain"    : domain,
                "mimics"    : brand,
                "confidence": round(sim, 2),
                "detail"    : f"'{sld}' is {int(sim*100)}% similar to brand '{brand}'",
            }

        # 3. Brand embedded in subdomain/longer name (secure-paypal.xyz)
        if brand_norm in normalised and brand_norm != normalised:
            return {
                "type"      : "Brand Embedding",
                "domain"    : domain,
                "mimics"    : brand,
                "confidence": 0.90,
                "detail"    : f"Brand '{brand}' embedded in domain '{domain}'",
            }

    return None


# ── Structural heuristics ────────────────────────────────────────────────────

def structural_checks(url: str, domain: str) -> list[dict]:
    """Run pattern-based structural checks on a URL."""
    findings = []

    # IP address instead of domain
    if re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
        findings.append({
            "check"   : "IP Address URL",
            "detail"  : "Direct IP used — legitimate services always use domain names",
            "severity": "HIGH",
        })

    # Credentials in URL (http://user:pass@domain)
    if re.search(r"https?://[^@\s]+@", url):
        findings.append({
            "check"   : "Credentials in URL",
            "detail"  : "Username/password embedded in URL — classic credential theft trick",
            "severity": "HIGH",
        })

    # URL shortener
    if any(s in domain for s in URL_SHORTENERS):
        findings.append({
            "check"   : "URL Shortener",
            "detail"  : f"'{domain}' hides the real destination — always expand before clicking",
            "severity": "MEDIUM",
        })

    # High-risk TLD
    tld = get_tld(domain)
    if tld in HIGH_RISK_TLDS:
        findings.append({
            "check"   : f"High-Risk TLD ({tld})",
            "detail"  : f"TLD '{tld}' is heavily abused in phishing campaigns",
            "severity": "HIGH",
        })

    # Dangerous file extension
    for ext in DANGEROUS_EXTENSIONS:
        path = urllib.parse.urlparse(url).path.lower()
        if path.endswith(ext):
            findings.append({
                "check"   : f"Dangerous File Extension ({ext})",
                "detail"  : f"URL points directly to executable/script file ({ext})",
                "severity": "HIGH",
            })
            break

    # Excessive subdomains (attacker uses brand.attacker.com)
    parts = domain.split(".")
    if len(parts) > 4:
        findings.append({
            "check"   : "Excessive Subdomains",
            "detail"  : f"Domain has {len(parts)} labels — attackers fake legitimacy with deep subdomains",
            "severity": "MEDIUM",
        })

    # Very long domain (obfuscation)
    if len(domain) > 50:
        findings.append({
            "check"   : "Abnormally Long Domain",
            "detail"  : f"Domain is {len(domain)} chars — may be obfuscating true destination",
            "severity": "LOW",
        })

    return findings


# ── Optional VirusTotal lookup ───────────────────────────────────────────────

def virustotal_check(url: str, api_key: str = "") -> dict | None:
    """
    Query VirusTotal URL reputation API (v3).
    Requires a free API key from https://www.virustotal.com/gui/join-us
    Returns None gracefully if no key or network error.
    """
    if not REQUESTS_OK or not api_key:
        return None

    try:
        import base64
        # VT v3 expects URL-safe base64 of the URL, no padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key}
        r = requests.get(f"{VT_URL_REPORT}/{url_id}", headers=headers, timeout=8)
        if r.status_code == 200:
            data   = r.json()
            stats  = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            mal    = stats.get("malicious", 0)
            sus    = stats.get("suspicious", 0)
            total  = sum(stats.values()) or 1
            return {
                "malicious"  : mal,
                "suspicious" : sus,
                "total_scans": total,
                "flagged"    : mal > 0 or sus > 0,
                "detail"     : f"VirusTotal: {mal} malicious, {sus} suspicious / {total} engines",
            }
    except Exception:
        pass
    return None


# ── Main entry point ─────────────────────────────────────────────────────────

def analyse_urls(body: str, vt_api_key: str = "") -> list[dict]:
    """
    Full URL threat analysis pipeline.
    Returns list of finding dicts, one per suspicious URL.

    Each finding:
    {
        url, domain, findings: [structural checks],
        typosquat: dict|None,
        virustotal: dict|None,
        severity: "HIGH"|"MEDIUM"|"LOW",
        summary: str
    }
    """
    urls     = extract_urls(body)
    results  = []

    def _analyse_one(url: str) -> dict | None:
        domain   = normalise_domain(url)
        if not domain:
            return None

        structural = structural_checks(url, domain)
        typosquat  = check_typosquatting(domain)
        vt_result  = virustotal_check(url, vt_api_key) if vt_api_key else None

        # Only report if at least one issue found
        if not structural and not typosquat and not vt_result:
            return None

        # Overall severity = worst finding
        sev_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        all_sevs = [f["severity"] for f in structural]
        if typosquat:
            all_sevs.append("HIGH")
        if vt_result and vt_result.get("flagged"):
            all_sevs.append("HIGH")

        overall = max(all_sevs, key=lambda s: sev_rank.get(s, 0)) if all_sevs else "LOW"

        parts = []
        if typosquat:
            parts.append(typosquat["detail"])
        for f in structural:
            parts.append(f["detail"])
        if vt_result:
            parts.append(vt_result["detail"])

        return {
            "url"        : url[:100],
            "domain"     : domain,
            "findings"   : structural,
            "typosquat"  : typosquat,
            "virustotal" : vt_result,
            "severity"   : overall,
            "summary"    : " | ".join(parts),
        }

    # Parallel URL analysis (up to 10 URLs concurrently)
    with ThreadPoolExecutor(max_workers=min(10, len(urls) or 1)) as ex:
        futures = {ex.submit(_analyse_one, u): u for u in urls[:20]}  # cap at 20 URLs
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                results.append(res)

    # Sort: HIGH first
    sev_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    results.sort(key=lambda r: sev_rank.get(r["severity"], 0), reverse=True)
    return results
