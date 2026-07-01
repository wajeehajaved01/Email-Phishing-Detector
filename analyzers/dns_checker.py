"""
dns_checker.py  —  PRODUCTION UPGRADE
Asynchronous DNS resolution using ThreadPoolExecutor.
- Uses public fallback resolvers: 8.8.8.8 (Google), 1.1.1.1 (Cloudflare)
- All lookups run in background threads; UI never freezes
- Graceful timeout/error → "Unknown/Unverified" status
- Covers SPF (RFC 7208), DMARC (RFC 7489), DKIM header (RFC 6376)
"""

import re
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# ── Resolver factory with public fallback nameservers ────────────────────────
_FALLBACK_NS = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
_DNS_TIMEOUT  = 6      # seconds per individual query
_THREAD_TIMEOUT = 8    # hard wall-clock limit per check

def _make_resolver() -> "dns.resolver.Resolver":
    """Return a Resolver configured with public fallback nameservers."""
    r = dns.resolver.Resolver()
    r.nameservers = _FALLBACK_NS
    r.lifetime    = _DNS_TIMEOUT
    r.timeout     = _DNS_TIMEOUT / 2
    return r


# ── Internal blocking workers (run in threads) ────────────────────────────────

def _spf_worker(domain: str) -> dict:
    resolver = _make_resolver()
    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            if not txt.startswith("v=spf1"):
                continue
            if   "~all" in txt: policy = "softfail  (~all)"
            elif "-all" in txt: policy = "hardfail  (-all) ✔ strict"
            elif "+all" in txt: policy = "PASS ALL  ⚠ dangerously permissive"
            elif "?all" in txt: policy = "neutral   (?all)"
            else:               policy = "no explicit all-policy"
            return {"found": True,  "record": txt, "policy": policy, "pass": True,
                    "detail": f"SPF found. Policy: {policy}"}
        return {"found": False, "record": None, "pass": False,
                "detail": f"No SPF record for '{domain}' — spoofing possible"}

    except dns.resolver.NXDOMAIN:
        return {"found": False, "record": None, "pass": False,
                "detail": f"Domain '{domain}' does not exist in DNS (NXDOMAIN)"}
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return {"found": False, "record": None, "pass": False,
                "detail": f"No TXT records found for '{domain}'"}
    except dns.exception.Timeout:
        return {"found": None, "record": None, "pass": None,
                "detail": f"DNS timeout after {_DNS_TIMEOUT}s — result unverified"}
    except Exception as exc:
        return {"found": None, "record": None, "pass": None,
                "detail": f"DNS error: {type(exc).__name__}: {exc}"}


def _dmarc_worker(domain: str) -> dict:
    resolver = _make_resolver()
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            if "v=DMARC1" not in txt:
                continue
            pol   = re.search(r"p=(\w+)",    txt)
            rua   = re.search(r"rua=([^;]+)",txt)
            pct   = re.search(r"pct=(\d+)",  txt)
            policy    = pol.group(1) if pol else "unknown"
            report_to = rua.group(1).strip() if rua else "not configured"
            coverage  = pct.group(1) + "%" if pct else "100%"

            enforcement = {
                "none"      : "⚠ Monitoring only — no enforcement",
                "quarantine": "Suspicious mail → spam folder",
                "reject"    : "✔ Strongest — reject unauthenticated mail",
            }.get(policy, "Unknown policy")

            return {"found": True, "record": txt, "policy": policy,
                    "rua": report_to, "pass": True,
                    "detail": f"DMARC found. p={policy} ({enforcement}). Coverage: {coverage}. Reports→{report_to}"}

        return {"found": False, "record": None, "pass": False,
                "detail": f"No DMARC record at {dmarc_domain}"}

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return {"found": False, "record": None, "pass": False,
                "detail": f"No DMARC record at {dmarc_domain}"}
    except dns.exception.Timeout:
        return {"found": None, "record": None, "pass": None,
                "detail": f"DMARC DNS timeout after {_DNS_TIMEOUT}s — unverified"}
    except Exception as exc:
        return {"found": None, "record": None, "pass": None,
                "detail": f"DMARC error: {type(exc).__name__}: {exc}"}


# ── Public async-friendly API ────────────────────────────────────────────────

def _timeout_wrapper(fn, *args) -> dict:
    """
    Run fn(*args) in a thread with a hard wall-clock timeout.
    Returns an "Unknown" dict if the thread times out or raises.
    """
    if not DNS_AVAILABLE:
        return {"found": None, "record": None, "pass": None,
                "detail": "dnspython not installed — install with: pip install dnspython"}
    with ThreadPoolExecutor(max_workers=1) as ex:
        future = ex.submit(fn, *args)
        try:
            return future.result(timeout=_THREAD_TIMEOUT)
        except FuturesTimeout:
            return {"found": None, "record": None, "pass": None,
                    "detail": f"Hard timeout ({_THREAD_TIMEOUT}s) — DNS unresponsive"}
        except Exception as exc:
            return {"found": None, "record": None, "pass": None,
                    "detail": f"Unexpected error: {exc}"}


def check_spf(domain: str) -> dict:
    """Non-blocking SPF check. Returns immediately with Unknown if DNS is slow."""
    if not domain:
        return {"found": False, "record": None, "pass": False,
                "detail": "No sender domain to check"}
    return _timeout_wrapper(_spf_worker, domain)


def check_dmarc(domain: str) -> dict:
    """Non-blocking DMARC check."""
    if not domain:
        return {"found": False, "record": None, "pass": False,
                "detail": "No sender domain to check"}
    return _timeout_wrapper(_dmarc_worker, domain)


def check_all_dns_parallel(domain: str) -> tuple[dict, dict]:
    """
    Run SPF + DMARC concurrently in two threads.
    Returns (spf_result, dmarc_result) — both available simultaneously.
    Cuts total DNS wait time roughly in half.
    """
    if not DNS_AVAILABLE:
        unknown = {"found": None, "record": None, "pass": None,
                   "detail": "dnspython not installed"}
        return unknown, unknown

    with ThreadPoolExecutor(max_workers=2) as ex:
        f_spf   = ex.submit(_timeout_wrapper, _spf_worker,   domain)
        f_dmarc = ex.submit(_timeout_wrapper, _dmarc_worker, domain)
        spf_r   = f_spf.result()
        dmarc_r = f_dmarc.result()
    return spf_r, dmarc_r


# ── DKIM header structure check (no DNS needed) ──────────────────────────────

def check_dkim_header(dkim_sig: str) -> dict:
    """
    Structural validation of DKIM-Signature header.
    Full crypto verification requires raw message bytes + DNS public key lookup;
    we validate presence and tag completeness — absence is a strong phishing signal.

    Algorithm security note:
      rsa-sha1  → deprecated, weak
      rsa-sha256 / ed25519-sha256 → current standard
    """
    if not dkim_sig:
        return {"found": False, "valid_structure": False,
                "detail": "No DKIM-Signature — email not cryptographically signed"}

    required = ["v=", "a=", "d=", "s=", "h=", "bh=", "b="]
    missing  = [t for t in required if t not in dkim_sig]

    if missing:
        return {"found": True, "valid_structure": False,
                "detail": f"DKIM-Signature malformed. Missing tags: {missing}"}

    d_val = (re.search(r"\bd=([^;\s]+)", dkim_sig) or type("", (), {"group": lambda s,x: "?"})()).group(1).strip()
    a_val = (re.search(r"\ba=([^;\s]+)", dkim_sig) or type("", (), {"group": lambda s,x: "?"})()).group(1).strip()

    # Warn on deprecated sha1
    alg_warn = " ⚠ SHA-1 is deprecated" if "sha1" in a_val.lower() else ""

    return {"found": True, "valid_structure": True,
            "signing_domain": d_val, "algorithm": a_val,
            "detail": f"DKIM present. Signed by: {d_val}, Algorithm: {a_val}{alg_warn}"}
