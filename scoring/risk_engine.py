"""
risk_engine.py  —  PRODUCTION UPGRADE
Algorithmic risk scoring with clear mathematical model.

═══════════════════════════════════════════════════════════════
SCORING FORMULA
═══════════════════════════════════════════════════════════════

Final Score = Σ(category_raw × category_weight) capped at 100

Categories and their maximum contributions:
  ┌─────────────────────────────┬──────────┬───────────────┐
  │ Category                    │ Max Pts  │ Rationale     │
  ├─────────────────────────────┼──────────┼───────────────┤
  │ DNS Authentication          │  50      │ Strongest     │
  │   - No SPF                  │ +20      │ cryptographic │
  │   - No DMARC                │ +18      │ signal        │
  │   - No/bad DKIM             │ +12      │               │
  ├─────────────────────────────┼──────────┼───────────────┤
  │ Header Spoofing Flags       │  25      │ Behavioral    │
  │   HIGH flag (×n)            │ +12 each │ indicators    │
  │   MEDIUM flag (×n)          │  +7 each │               │
  │   LOW flag (×n)             │  +2 each │               │
  ├─────────────────────────────┼──────────┼───────────────┤
  │ URL / Threat Intelligence   │  35      │ Direct harm   │
  │   Typosquatting             │ +15 each │ vectors       │
  │   Structural HIGH           │ +10 each │               │
  │   Structural MEDIUM         │  +5 each │               │
  ├─────────────────────────────┼──────────┼───────────────┤
  │ Phishing Keywords           │  20      │ Content       │
  │   HIGH keyword (×n)         │  +8 each │ analysis      │
  │   MEDIUM keyword (×n)       │  +4 each │               │
  │   LOW keyword               │  +1 each │               │
  ├─────────────────────────────┼──────────┼───────────────┤
  │ Structural Extras           │  10      │ Supporting    │
  │   Tracking pixels           │  +4 each │ evidence      │
  │   Suspicious attachments    │  +6 each │               │
  └─────────────────────────────┴──────────┴───────────────┘

Thresholds:
  0–34  → LOW RISK    (green)
  35–64 → MEDIUM RISK (yellow)
  65+   → HIGH RISK   (red)

Calibration notes:
  - A legitimate email with SPF+DMARC+DKIM all passing and no keywords
    will score 0 even with some benign header quirks.
  - A classic phishing email (no DNS auth + spoofed Reply-To + keywords)
    will score 65-85 purely from structural signals, before URL analysis.
  - URL typosquatting alone (+15) is enough to push to MEDIUM.
═══════════════════════════════════════════════════════════════
"""

# ── Weight tables ────────────────────────────────────────────────────────────

W_DNS = {
    "no_spf"         : 20,
    "no_dmarc"       : 18,
    "no_dkim"        : 12,
    "dkim_malformed" :  8,
    "dmarc_none_pol" :  5,   # DMARC exists but policy=none (monitoring only)
    "spf_pass_all"   : 10,   # SPF "+all" — dangerously permissive
}

W_SPOOF = {
    "HIGH"  : 12,
    "MEDIUM":  7,
    "LOW"   :  2,
}

W_URL = {
    "typosquat_high" : 15,   # confidence >= 0.90
    "typosquat_med"  : 10,   # confidence 0.82–0.89
    "structural_HIGH": 10,
    "structural_MED" :  5,
    "structural_LOW" :  2,
    "virustotal_flag": 20,   # if VT flags it — very high confidence
}

W_KW = {
    "HIGH"  :  8,
    "MEDIUM":  4,
    "LOW"   :  1,
}

W_EXTRA = {
    "tracking_pixel"        :  4,
    "suspicious_attachment" :  6,
}

DANGEROUS_ATTACHMENT_TYPES = {
    "application/x-msdownload", "application/x-executable",
    "application/x-msdos-program", "application/octet-stream",
    "application/x-sh", "application/x-bat",
    "application/vnd.ms-office",
}
DANGEROUS_ATTACHMENT_EXTS  = {".exe", ".bat", ".cmd", ".vbs", ".js", ".msi",
                               ".ps1", ".scr", ".pif", ".hta"}

HARD_CAP = 100


# ── Scoring engine ───────────────────────────────────────────────────────────

def calculate_risk(results: dict) -> dict:
    """
    Aggregate all analysis results into a single risk score and verdict.

    Input:  results dict from main.py (headers, spf, dmarc, dkim,
                                       spoofing, keywords, urls, ...)
    Output: {raw_score, display_score, verdict, color, label, breakdown,
             category_scores, confidence}
    """
    score     = 0
    breakdown = []

    # ── 1. DNS Authentication (max ~50 pts) ──────────────────────────────
    cat_dns = 0

    spf = results.get("spf", {})
    if spf.get("found") is False:
        pts = W_DNS["no_spf"]
        cat_dns += pts
        breakdown.append({"category": "DNS", "check": "No SPF Record",
                           "pts": pts, "severity": "HIGH"})
    elif spf.get("found") is True:
        policy = spf.get("policy", "")
        if "+all" in policy:
            pts = W_DNS["spf_pass_all"]
            cat_dns += pts
            breakdown.append({"category": "DNS", "pts": pts, "severity": "HIGH",
                               "check": "SPF Policy '+all' — accepts mail from ANY server"})

    dmarc = results.get("dmarc", {})
    if dmarc.get("found") is False:
        pts = W_DNS["no_dmarc"]
        cat_dns += pts
        breakdown.append({"category": "DNS", "check": "No DMARC Record",
                           "pts": pts, "severity": "HIGH"})
    elif dmarc.get("found") is True and dmarc.get("policy") == "none":
        pts = W_DNS["dmarc_none_pol"]
        cat_dns += pts
        breakdown.append({"category": "DNS", "pts": pts, "severity": "MEDIUM",
                           "check": "DMARC policy=none — monitoring only, no enforcement"})

    dkim = results.get("dkim", {})
    if not dkim.get("found"):
        pts = W_DNS["no_dkim"]
        cat_dns += pts
        breakdown.append({"category": "DNS", "check": "No DKIM Signature",
                           "pts": pts, "severity": "HIGH"})
    elif not dkim.get("valid_structure"):
        pts = W_DNS["dkim_malformed"]
        cat_dns += pts
        breakdown.append({"category": "DNS", "check": "DKIM-Signature Malformed",
                           "pts": pts, "severity": "MEDIUM"})

    score += cat_dns

    # ── 2. Header Spoofing (max ~25 pts) ─────────────────────────────────
    cat_spoof = 0
    for flag in results.get("spoofing", []):
        sev = flag.get("severity", "LOW")
        pts = W_SPOOF.get(sev, 2)
        cat_spoof += pts
        breakdown.append({"category": "Spoofing", "check": flag["check"],
                           "pts": pts, "severity": sev})
    score += cat_spoof

    # ── 3. URL & Threat Intelligence (max ~35 pts) ────────────────────────
    cat_url = 0
    for url_finding in results.get("url_threats", []):
        # Typosquatting
        typo = url_finding.get("typosquat")
        if typo:
            conf = typo.get("confidence", 0)
            pts  = W_URL["typosquat_high"] if conf >= 0.90 else W_URL["typosquat_med"]
            cat_url += pts
            breakdown.append({"category": "URL", "pts": pts, "severity": "HIGH",
                               "check": f"Typosquatting: {typo['detail']}"})

        # VirusTotal
        vt = url_finding.get("virustotal")
        if vt and vt.get("flagged"):
            pts = W_URL["virustotal_flag"]
            cat_url += pts
            breakdown.append({"category": "URL", "pts": pts, "severity": "HIGH",
                               "check": f"VirusTotal flagged: {vt['detail']}"})

        # Structural findings
        for finding in url_finding.get("findings", []):
            sev = finding.get("severity", "LOW")
            pts = W_URL.get(f"structural_{sev[:3].upper()}", 2)
            cat_url += pts
            breakdown.append({"category": "URL", "pts": pts, "severity": sev,
                               "check": f"{finding['check']}: {url_finding['domain']}"})

    # Legacy url format fallback (from old keyword_analyzer.scan_urls)
    for url in results.get("urls", []):
        if isinstance(url, dict) and "reason" in url:
            cat_url += 8
            breakdown.append({"category": "URL", "pts": 8, "severity": "HIGH",
                               "check": f"Suspicious URL: {url.get('reason','')}"})
    score += cat_url

    # ── 4. Phishing Keywords (max ~20 pts) ───────────────────────────────
    cat_kw = 0
    for kw in results.get("keywords", []):
        sev = kw.get("severity", "LOW")
        pts = W_KW.get(sev, 1)
        cat_kw += pts
        breakdown.append({"category": "Keywords",
                           "check": f'Keyword: "{kw["keyword"]}"',
                           "pts": pts, "severity": sev})
    score += cat_kw

    # ── 5. Structural Extras ──────────────────────────────────────────────
    cat_extra = 0
    headers = results.get("headers", {})

    # Tracking pixels
    for px in headers.get("tracking_pixels", []):
        pts = W_EXTRA["tracking_pixel"]
        cat_extra += pts
        breakdown.append({"category": "Extra", "pts": pts, "severity": "LOW",
                           "check": f"Tracking pixel: {px[:60]}"})
        break  # count max 1 tracking pixel finding

    # Dangerous attachments
    for att in headers.get("attachments", []):
        fname = att.get("filename", "").lower()
        ftype = att.get("type", "").lower()
        ext   = "." + fname.rsplit(".", 1)[-1] if "." in fname else ""
        if ext in DANGEROUS_ATTACHMENT_EXTS or ftype in DANGEROUS_ATTACHMENT_TYPES:
            pts = W_EXTRA["suspicious_attachment"]
            cat_extra += pts
            breakdown.append({"category": "Extra", "pts": pts, "severity": "HIGH",
                               "check": f"Dangerous attachment: {att['filename']} ({ftype})"})

    score += cat_extra

    # ── Verdict ───────────────────────────────────────────────────────────
    display_score = min(score, HARD_CAP)

    if display_score >= 65:
        verdict = "HIGH RISK"
        color   = "RED"
        label   = "🔴 LIKELY PHISHING — Do NOT click links or provide any information"
    elif display_score >= 35:
        verdict = "MEDIUM RISK"
        color   = "YELLOW"
        label   = "🟡 SUSPICIOUS — Verify sender identity through separate channel"
    else:
        verdict = "LOW RISK"
        color   = "GREEN"
        label   = "🟢 APPEARS LEGITIMATE — Authentication checks passed"

    # Confidence: how many categories contributed
    active_cats = sum([
        cat_dns > 0, cat_spoof > 0,
        cat_url > 0, cat_kw > 0, cat_extra > 0,
    ])
    confidence = ("HIGH" if active_cats >= 3 else
                  "MEDIUM" if active_cats >= 2 else "LOW")

    return {
        "raw_score"    : score,
        "display_score": display_score,
        "verdict"      : verdict,
        "color"        : color,
        "label"        : label,
        "breakdown"    : breakdown,
        "category_scores": {
            "DNS Authentication": cat_dns,
            "Header Spoofing"   : cat_spoof,
            "URL / Threats"     : cat_url,
            "Keywords"          : cat_kw,
            "Extras"            : cat_extra,
        },
        "confidence"   : confidence,
    }
