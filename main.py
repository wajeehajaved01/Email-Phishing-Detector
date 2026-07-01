"""
main.py  —  PRODUCTION UPGRADE
Orchestrator: wires all modules together.
Uses parallel DNS resolution for speed.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

from analyzers.email_parser     import parse_email
from analyzers.header_analyzer  import check_spoofing
from analyzers.dns_checker      import check_all_dns_parallel, check_dkim_header
from analyzers.keyword_analyzer import scan_keywords
from analyzers.url_threat       import analyse_urls
from scoring.risk_engine        import calculate_risk
from report.report_generator    import print_report, save_report

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║     EMAIL PHISHING DETECTION SYSTEM  v2.0  (Production)     ║
║     IS Lab Project  |  Async DNS  |  Threat Intelligence     ║
╚══════════════════════════════════════════════════════════════╝
"""

def analyze(raw: str, vt_api_key: str = "") -> dict:
    """Full async analysis pipeline."""
    headers = parse_email(raw)
    domain  = headers.get("sender_domain", "")

    # DNS: SPF + DMARC run in parallel threads
    spf, dmarc = check_all_dns_parallel(domain)
    dkim        = check_dkim_header(headers.get("dkim_signature", ""))
    spoof       = check_spoofing(headers)
    kw          = scan_keywords(headers.get("body", ""))
    url_threats = analyse_urls(headers.get("body", ""), vt_api_key)

    results = {
        "headers"    : headers,
        "spf"        : spf,
        "dmarc"      : dmarc,
        "dkim"       : dkim,
        "spoofing"   : spoof,
        "keywords"   : kw,
        "url_threats": url_threats,
        "urls"       : [],   # legacy field kept for GUI compatibility
    }
    results["risk"] = calculate_risk(results)
    return results


def main():
    print(BANNER)
    print("  [1] Analyze a .eml file")
    print("  [2] Paste raw email headers/body")
    print("  [3] Run demo with built-in test emails")
    choice = input("\n  Select option (1/2/3): ").strip()

    if choice == "1":
        path = input("  Enter path to .eml file: ").strip()
        if not os.path.exists(path):
            print(f"  ERROR: File not found: {path}")
            sys.exit(1)
        with open(path, "r", errors="replace") as f:
            raw = f.read()

    elif choice == "2":
        print("  Paste email content below. Type END on a new line when done:\n")
        lines = []
        while True:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
        raw = "\n".join(lines)

    elif choice == "3":
        demo_dir = os.path.join(os.path.dirname(__file__), "samples")
        samples  = [f for f in os.listdir(demo_dir) if f.endswith(".eml")]
        if not samples:
            print("  No .eml files found in samples/ folder.")
            sys.exit(1)
        print("\n  Available demo emails:")
        for i, s in enumerate(samples, 1):
            print(f"    [{i}] {s}")
        idx = int(input("  Choose sample: ")) - 1
        with open(os.path.join(demo_dir, samples[idx]), "r", errors="replace") as f:
            raw = f.read()
    else:
        print("  Invalid option.")
        sys.exit(1)

    print("\n  Analyzing (DNS lookups running in background)...\n")
    results = analyze(raw)
    print_report(results)

    if input("\n  Save report to file? (y/n): ").strip().lower() == "y":
        out = save_report(results)
        print(f"  Report saved: {out}")


if __name__ == "__main__":
    main()
