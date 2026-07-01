"""
email_parser.py  —  PRODUCTION UPGRADE
Production-grade MIME email parser using Python's email module.
Handles:
  - Multipart MIME (text/plain, text/html, mixed, alternative, related)
  - Encoded headers (RFC 2047 — =?UTF-8?B?...?= style)
  - Tracking pixel detection (1x1 img tags)
  - Attachment enumeration
  - Full received-chain parsing
  - Character encoding fallbacks
"""

import email
import email.policy
import email.header
import re
import html
from email.utils import parseaddr, getaddresses


# ── Header decoding ──────────────────────────────────────────────────────────

def _decode_header(raw: str) -> str:
    """
    Decode RFC 2047 encoded headers like =?UTF-8?B?SGVsbG8=?=
    Falls back gracefully on encoding errors.
    """
    if not raw:
        return ""
    try:
        parts = email.header.decode_header(raw)
        decoded = []
        for part, charset in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                decoded.append(str(part))
        return " ".join(decoded).strip()
    except Exception:
        return str(raw).strip()


def extract_domain(address: str) -> str:
    """Extract domain from 'Name <user@domain.com>' or 'user@domain.com'."""
    _, addr = parseaddr(address)
    if "@" in addr:
        return addr.split("@", 1)[1].lower().strip()
    # Fallback regex for malformed addresses
    m = re.search(r"@([\w.\-]+)", address)
    return m.group(1).lower() if m else ""


# ── Body extraction ──────────────────────────────────────────────────────────

def _get_body(msg: email.message.Message) -> tuple[str, str, list]:
    """
    Recursively walk MIME structure.
    Returns: (plain_text, html_text, attachments_list)

    Handles: multipart/mixed, multipart/alternative, multipart/related,
             text/plain, text/html, inline images, attachments
    """
    plain_parts  = []
    html_parts   = []
    attachments  = []

    def _walk(part: email.message.Message):
        ct   = part.get_content_type()
        disp = part.get_content_disposition() or ""

        if part.is_multipart():
            for sub in part.get_payload():
                _walk(sub)
            return

        # Attachment
        if "attachment" in disp or (part.get_filename() and ct not in ("text/plain", "text/html")):
            attachments.append({
                "filename": part.get_filename() or "unnamed",
                "type"    : ct,
                "size_bytes": len(part.get_payload(decode=True) or b""),
            })
            return

        # Decode payload
        try:
            raw_bytes = part.get_payload(decode=True) or b""
            charset   = part.get_content_charset() or "utf-8"
            text      = raw_bytes.decode(charset, errors="replace")
        except Exception:
            text = str(part.get_payload())

        if ct == "text/plain":
            plain_parts.append(text)
        elif ct == "text/html":
            html_parts.append(text)

    _walk(msg)

    plain = "\n".join(plain_parts)
    html_body = "\n".join(html_parts)

    # If no plain text, strip HTML tags as fallback
    if not plain.strip() and html_body:
        plain = _html_to_text(html_body)

    return plain, html_body, attachments


def _html_to_text(html_str: str) -> str:
    """Minimal HTML→text: strip tags, decode entities."""
    text = re.sub(r"<style[^>]*>.*?</style>", " ", html_str, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<script[^>]*>.*?</script>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\s{2,}", " ", text)
    return text.strip()


def _detect_tracking_pixels(html_str: str) -> list[str]:
    """
    Find 1x1 tracking pixels — common in phishing to confirm email opens.
    Returns list of src URLs.
    """
    pattern = r'<img[^>]+(?:width=["\']?1["\']?|height=["\']?1["\']?)[^>]+src=["\']([^"\']+)["\']'
    return re.findall(pattern, html_str, re.IGNORECASE)


# ── Received chain analysis ──────────────────────────────────────────────────

def _parse_received_chain(received_headers: list[str]) -> list[dict]:
    """
    Parse Received headers to map email routing hops.
    Useful for detecting forged origins.
    """
    hops = []
    for hdr in (received_headers or []):
        # Extract 'from' server
        from_m  = re.search(r"from\s+([\w.\-\[\]]+)", hdr, re.IGNORECASE)
        by_m    = re.search(r"by\s+([\w.\-]+)",        hdr, re.IGNORECASE)
        ip_m    = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", hdr)
        date_m  = re.search(r";\s*(.+)$", hdr.strip())
        hops.append({
            "from_server": from_m.group(1) if from_m else "?",
            "by_server"  : by_m.group(1)   if by_m   else "?",
            "ip"         : ip_m.group(1)    if ip_m   else None,
            "date"       : date_m.group(1).strip() if date_m else None,
        })
    return hops


# ── Main parser ──────────────────────────────────────────────────────────────

def parse_email(raw: str) -> dict:
    """
    Full production email parser.
    Accepts raw email string (paste or .eml file content).
    Returns structured dict with all security-relevant fields.
    """
    # Use email.policy.compat32 for broad compatibility with real-world emails
    try:
        msg = email.message_from_string(raw, policy=email.policy.compat32)
    except Exception:
        msg = email.message_from_string(raw)

    # ── Decode headers ────────────────────────────────────────────────────
    from_raw      = _decode_header(msg.get("From",         ""))
    reply_to_raw  = _decode_header(msg.get("Reply-To",     ""))
    return_path   = _decode_header(msg.get("Return-Path",  ""))
    message_id    = msg.get("Message-ID", "")
    subject       = _decode_header(msg.get("Subject",      ""))
    date          = _decode_header(msg.get("Date",         ""))
    dkim_sig      = msg.get("DKIM-Signature",               "")
    x_mailer      = msg.get("X-Mailer",                     "")
    x_orig_ip     = msg.get("X-Originating-IP",             "")
    x_spam_flag   = msg.get("X-Spam-Flag",                  "")
    x_spam_status = msg.get("X-Spam-Status",                "")
    received      = msg.get_all("Received") or []

    # ── Body extraction ───────────────────────────────────────────────────
    plain, html_body, attachments = _get_body(msg)

    # Combined text for keyword scanning (both plain + HTML text)
    body_for_scan = plain + "\n" + _html_to_text(html_body)

    # ── Tracking pixels ───────────────────────────────────────────────────
    tracking_pixels = _detect_tracking_pixels(html_body)

    # ── Domain extraction ─────────────────────────────────────────────────
    sender_domain = extract_domain(from_raw)
    reply_domain  = extract_domain(reply_to_raw)
    return_domain = extract_domain(return_path)
    msgid_domain  = extract_domain(message_id)

    # ── Received chain ────────────────────────────────────────────────────
    received_hops = _parse_received_chain(received)

    return {
        # Raw headers
        "from"           : from_raw,
        "reply_to"       : reply_to_raw,
        "return_path"    : return_path,
        "message_id"     : message_id,
        "subject"        : subject,
        "date"           : date,
        "dkim_signature" : dkim_sig,
        "x_mailer"       : x_mailer,
        "x_originating_ip": x_orig_ip,
        "x_spam_flag"    : x_spam_flag,
        "x_spam_status"  : x_spam_status,
        "received"       : received,

        # Parsed body
        "body"           : body_for_scan,
        "plain_text"     : plain,
        "html_body"      : html_body,

        # Attachments
        "attachments"    : attachments,

        # Tracking
        "tracking_pixels": tracking_pixels,

        # Domain fields (used by all analyzers)
        "sender_domain"  : sender_domain,
        "reply_domain"   : reply_domain,
        "return_domain"  : return_domain,
        "msgid_domain"   : msgid_domain,

        # Routing
        "received_hops"  : received_hops,
    }
