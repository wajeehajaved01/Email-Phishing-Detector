"""
report_generator.py
Generates colored terminal report + plain-text file report.
"""

import os
import datetime

try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False

    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = BLUE = ""
    class Style:
        BRIGHT = RESET_ALL = DIM = ""
    class Back:
        RED = GREEN = YELLOW = ""


SEV_COLOR = {
    "HIGH"  : Fore.RED   + Style.BRIGHT,
    "MEDIUM": Fore.YELLOW + Style.BRIGHT,
    "LOW"   : Fore.CYAN,
}

VERDICT_COLOR = {
    "RED"   : Back.RED    + Fore.WHITE + Style.BRIGHT,
    "YELLOW": Back.YELLOW + Fore.BLACK + Style.BRIGHT,
    "GREEN" : Back.GREEN  + Fore.BLACK + Style.BRIGHT,
}


def _bar(score: int, width: int = 40) -> str:
    filled = int((score / 100) * width)
    if score >= 65:
        c = Fore.RED
    elif score >= 35:
        c = Fore.YELLOW
    else:
        c = Fore.GREEN
    return c + "█" * filled + Style.DIM + "░" * (width - filled) + Style.RESET_ALL


def _line(char="─", width=68):
    return Fore.CYAN + char * width + Style.RESET_ALL


def print_report(results: dict):
    h   = results["headers"]
    spf = results["spf"]
    dmarc = results["dmarc"]
    dkim  = results["dkim"]
    risk  = results["risk"]

    print(_line("═"))
    print(Fore.CYAN + Style.BRIGHT +
          "   📧  EMAIL PHISHING ANALYSIS REPORT" + Style.RESET_ALL)
    print(_line("═"))

    # ── Email metadata ──────────────────────────────────────────
    print(f"\n{Style.BRIGHT}  EMAIL METADATA{Style.RESET_ALL}")
    print(_line())
    print(f"  From        : {Fore.WHITE}{h.get('from','—')}{Style.RESET_ALL}")
    print(f"  Reply-To    : {Fore.WHITE}{h.get('reply_to','—')}{Style.RESET_ALL}")
    print(f"  Return-Path : {Fore.WHITE}{h.get('return_path','—')}{Style.RESET_ALL}")
    print(f"  Subject     : {Fore.WHITE}{h.get('subject','—')}{Style.RESET_ALL}")
    print(f"  Date        : {Fore.WHITE}{h.get('date','—')}{Style.RESET_ALL}")
    print(f"  Sender Domain: {Fore.YELLOW + Style.BRIGHT}{h.get('sender_domain','—')}{Style.RESET_ALL}")

    # ── DNS Authentication ──────────────────────────────────────
    print(f"\n{Style.BRIGHT}  DNS AUTHENTICATION CHECKS{Style.RESET_ALL}")
    print(_line())

    def auth_line(label, check_dict):
        if check_dict.get("found") is None:
            status = Fore.CYAN + "SKIP (DNS unavailable)"
        elif check_dict.get("found"):
            status = Fore.GREEN + Style.BRIGHT + "✔ FOUND"
        else:
            status = Fore.RED + Style.BRIGHT + "✘ NOT FOUND"
        detail = check_dict.get("detail", "")
        print(f"  {label:<10}: {status}{Style.RESET_ALL}  —  {detail}")

    auth_line("SPF",   spf)
    auth_line("DMARC", dmarc)

    if dkim.get("found"):
        if dkim.get("valid_structure"):
            dk_status = Fore.GREEN + Style.BRIGHT + "✔ PRESENT & VALID STRUCTURE"
        else:
            dk_status = Fore.YELLOW + Style.BRIGHT + "⚠ PRESENT BUT MALFORMED"
    else:
        dk_status = Fore.RED + Style.BRIGHT + "✘ NOT PRESENT"
    print(f"  {'DKIM':<10}: {dk_status}{Style.RESET_ALL}  —  {dkim.get('detail','')}")

    # ── Spoofing flags ──────────────────────────────────────────
    spoof_flags = results.get("spoofing", [])
    print(f"\n{Style.BRIGHT}  HEADER ANOMALY CHECKS  ({len(spoof_flags)} flags){Style.RESET_ALL}")
    print(_line())
    if not spoof_flags:
        print(f"  {Fore.GREEN}No header anomalies detected.{Style.RESET_ALL}")
    else:
        for f in spoof_flags:
            c = SEV_COLOR.get(f["severity"], "")
            print(f"  {c}[{f['severity']:<6}]{Style.RESET_ALL}  {f['check']}")
            print(f"           {Style.DIM}{f['detail']}{Style.RESET_ALL}")

    # ── Keywords ────────────────────────────────────────────────
    kws = results.get("keywords", [])
    print(f"\n{Style.BRIGHT}  PHISHING KEYWORD SCAN  ({len(kws)} found){Style.RESET_ALL}")
    print(_line())
    if not kws:
        print(f"  {Fore.GREEN}No phishing keywords detected.{Style.RESET_ALL}")
    else:
        for k in kws:
            c = SEV_COLOR.get(k["severity"], "")
            print(f"  {c}[{k['severity']:<6}]{Style.RESET_ALL}  \"{k['keyword']}\"")

    # ── URLs ────────────────────────────────────────────────────
    urls = results.get("urls", [])
    print(f"\n{Style.BRIGHT}  SUSPICIOUS URL SCAN  ({len(urls)} flagged){Style.RESET_ALL}")
    print(_line())
    if not urls:
        print(f"  {Fore.GREEN}No suspicious URLs detected.{Style.RESET_ALL}")
    else:
        for u in urls:
            print(f"  {Fore.RED + Style.BRIGHT}[HIGH]{Style.RESET_ALL}  {u['url']}")
            print(f"           {Style.DIM}Reason: {u['reason']}{Style.RESET_ALL}")

    # ── Risk score ──────────────────────────────────────────────
    score   = risk["display_score"]
    verdict = risk["verdict"]
    label   = risk["label"]
    vc      = VERDICT_COLOR.get(risk["color"], "")

    print(f"\n{Style.BRIGHT}  RISK SCORE{Style.RESET_ALL}")
    print(_line())
    print(f"  Score : {score}/100   {_bar(score)}")
    print(f"\n  {vc}  {verdict} — {score}/100  {Style.RESET_ALL}")
    print(f"\n  {label}")

    # ── Breakdown ───────────────────────────────────────────────
    print(f"\n{Style.BRIGHT}  SCORE BREAKDOWN{Style.RESET_ALL}")
    print(_line())
    for item in risk["breakdown"]:
        c = SEV_COLOR.get(item["severity"], "")
        print(f"  {c}+{item['pts']:>3} pts{Style.RESET_ALL}  {item['check']}")

    # ── Recommendations ─────────────────────────────────────────
    print(f"\n{Style.BRIGHT}  SECURITY RECOMMENDATIONS{Style.RESET_ALL}")
    print(_line())
    _print_recommendations(results, risk)

    print(_line("═") + "\n")


def _print_recommendations(results, risk):
    recs = []
    if not results["spf"]["found"]:
        recs.append("Domain lacks SPF — easily spoofed. Sender's admin should add SPF record.")
    if not results["dmarc"]["found"]:
        recs.append("No DMARC policy — receivers cannot enforce authentication failures.")
    if not results["dkim"]["found"]:
        recs.append("Email is not DKIM-signed — integrity of headers cannot be verified.")
    if results["spoofing"]:
        recs.append("Header anomalies detected — do NOT reply to this email.")
    if results["keywords"]:
        recs.append("Phishing language detected — avoid clicking links or providing credentials.")
    if results["urls"]:
        recs.append("Suspicious URLs found — do NOT click. Use VirusTotal to verify links.")
    if risk["verdict"] == "HIGH RISK":
        recs.append("Report this email to your IT/security team immediately.")
        recs.append("Delete the email and do not forward it.")

    if not recs:
        recs.append("No immediate action required. Always remain cautious with unsolicited emails.")

    for i, r in enumerate(recs, 1):
        print(f"  {i}. {r}")


def save_report(results: dict, out_dir: str = ".") -> str:
    """Save plain-text report to file."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = os.path.join(out_dir, f"phishing_report_{timestamp}.txt")

    h    = results["headers"]
    risk = results["risk"]

    lines = [
        "=" * 68,
        "  EMAIL PHISHING ANALYSIS REPORT",
        f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 68,
        "",
        "EMAIL METADATA",
        "-" * 40,
        f"  From        : {h.get('from','—')}",
        f"  Reply-To    : {h.get('reply_to','—')}",
        f"  Subject     : {h.get('subject','—')}",
        f"  Sender Domain: {h.get('sender_domain','—')}",
        "",
        "DNS AUTHENTICATION",
        "-" * 40,
        f"  SPF  : {'FOUND' if results['spf']['found'] else 'NOT FOUND'}  — {results['spf']['detail']}",
        f"  DMARC: {'FOUND' if results['dmarc']['found'] else 'NOT FOUND'}  — {results['dmarc']['detail']}",
        f"  DKIM : {'PRESENT' if results['dkim']['found'] else 'NOT PRESENT'}  — {results['dkim']['detail']}",
        "",
        "RISK ASSESSMENT",
        "-" * 40,
        f"  Score  : {risk['display_score']}/100",
        f"  Verdict: {risk['verdict']}",
        f"  {risk['label']}",
        "",
        "SCORE BREAKDOWN",
        "-" * 40,
    ]
    for item in risk["breakdown"]:
        lines.append(f"  +{item['pts']:>3} pts  [{item['severity']}]  {item['check']}")

    lines += ["", "=" * 68]

    with open(filename, "w") as f:
        f.write("\n".join(lines))

    return filename
