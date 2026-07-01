"""
report_generator.py  —  PRODUCTION UPGRADE
Color terminal report + plain-text file report.
Handles new url_threats format from url_threat.py.
"""

import os, datetime

try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
    class Fore:
        RED=GREEN=YELLOW=CYAN=WHITE=MAGENTA=BLUE=""
    class Style:
        BRIGHT=RESET_ALL=DIM=""
    class Back:
        RED=GREEN=YELLOW=""

SEV = {
    "HIGH"  : Fore.RED    + Style.BRIGHT,
    "MEDIUM": Fore.YELLOW + Style.BRIGHT,
    "LOW"   : Fore.CYAN,
}
VCOLOR = {
    "RED"   : Back.RED    + Fore.WHITE + Style.BRIGHT,
    "YELLOW": Back.YELLOW + Fore.BLACK + Style.BRIGHT,
    "GREEN" : Back.GREEN  + Fore.BLACK + Style.BRIGHT,
}

def _bar(score, w=42):
    filled = int((score/100)*w)
    c = Fore.RED if score>=65 else Fore.YELLOW if score>=35 else Fore.GREEN
    return c + "█"*filled + Style.DIM + "░"*(w-filled) + Style.RESET_ALL

def _line(ch="─", w=70):
    return Fore.CYAN + ch*w + Style.RESET_ALL

def print_report(results: dict):
    h    = results["headers"]
    risk = results["risk"]
    score = risk["display_score"]
    vc    = VCOLOR.get(risk["color"], "")

    print(_line("═"))
    print(Fore.CYAN + Style.BRIGHT + "   📧  EMAIL PHISHING ANALYSIS REPORT  v2.0" + Style.RESET_ALL)
    print(_line("═"))

    # Metadata
    print(f"\n{Style.BRIGHT}  EMAIL METADATA{Style.RESET_ALL}")
    print(_line())
    for label, key in [("From","from"),("Reply-To","reply_to"),
                        ("Return-Path","return_path"),("Subject","subject"),
                        ("Date","date"),("Sender Domain","sender_domain")]:
        print(f"  {label:<14}: {Fore.WHITE}{h.get(key,'—')}{Style.RESET_ALL}")

    atts = h.get("attachments",[])
    if atts:
        print(f"  {'Attachments':<14}: {Fore.YELLOW}{len(atts)} file(s){Style.RESET_ALL}")
        for a in atts:
            print(f"    • {a['filename']} ({a['type']}, {a['size_bytes']} bytes)")

    if h.get("tracking_pixels"):
        print(f"  {'Tracking Pixels':<14}: {Fore.YELLOW}{len(h['tracking_pixels'])} detected{Style.RESET_ALL}")

    # DNS
    print(f"\n{Style.BRIGHT}  DNS AUTHENTICATION{Style.RESET_ALL}")
    print(_line())
    for label, d in [("SPF", results["spf"]),
                      ("DMARC", results["dmarc"])]:
        v = d.get("found")
        if v is True:    s = Fore.GREEN + Style.BRIGHT + "✔ FOUND    "
        elif v is False: s = Fore.RED   + Style.BRIGHT + "✘ NOT FOUND"
        else:            s = Fore.YELLOW+ Style.BRIGHT + "? UNKNOWN  "
        print(f"  {label:<8}: {s}{Style.RESET_ALL}  {d.get('detail','')[:60]}")

    dk = results["dkim"]
    if dk.get("found"):
        ds = (Fore.GREEN+"✔ PRESENT  ") if dk.get("valid_structure") else (Fore.YELLOW+"⚠ MALFORMED")
    else:
        ds = Fore.RED + Style.BRIGHT + "✘ NOT PRESENT"
    print(f"  {'DKIM':<8}: {ds}{Style.RESET_ALL}  {dk.get('detail','')[:60]}")

    # Header flags
    flags = results.get("spoofing",[])
    print(f"\n{Style.BRIGHT}  HEADER ANOMALY CHECKS  ({len(flags)} flags){Style.RESET_ALL}")
    print(_line())
    if not flags:
        print(f"  {Fore.GREEN}No anomalies detected.{Style.RESET_ALL}")
    else:
        for f in flags:
            c = SEV.get(f["severity"],"")
            print(f"  {c}[{f['severity']:<6}]{Style.RESET_ALL}  {f['check']}")
            print(f"           {Style.DIM}{f['detail']}{Style.RESET_ALL}")

    # URL Threats
    uts = results.get("url_threats",[])
    print(f"\n{Style.BRIGHT}  URL THREAT INTELLIGENCE  ({len(uts)} suspicious){Style.RESET_ALL}")
    print(_line())
    if not uts:
        print(f"  {Fore.GREEN}No suspicious URLs detected.{Style.RESET_ALL}")
    else:
        for ut in uts:
            c = SEV.get(ut["severity"],"")
            print(f"  {c}[{ut['severity']:<6}]{Style.RESET_ALL}  {ut['domain']}")
            print(f"           {Style.DIM}{ut['summary'][:80]}{Style.RESET_ALL}")

    # Keywords
    kws = results.get("keywords",[])
    print(f"\n{Style.BRIGHT}  PHISHING KEYWORDS  ({len(kws)} found){Style.RESET_ALL}")
    print(_line())
    if not kws:
        print(f"  {Fore.GREEN}No phishing keywords detected.{Style.RESET_ALL}")
    else:
        for k in kws:
            c = SEV.get(k["severity"],"")
            print(f"  {c}[{k['severity']:<6}]{Style.RESET_ALL}  \"{k['keyword']}\"")

    # Category scores
    cat_scores = risk.get("category_scores",{})
    print(f"\n{Style.BRIGHT}  CATEGORY SCORE BREAKDOWN{Style.RESET_ALL}")
    print(_line())
    for cat, pts in cat_scores.items():
        bar_w = int((pts / max(pts,1)) * 20) if pts > 0 else 0
        c = Fore.RED if pts>=15 else Fore.YELLOW if pts>=5 else Fore.GREEN
        print(f"  {cat:<22}: {c}{pts:>3} pts{Style.RESET_ALL}  {c}{'█'*min(pts,25)}{Style.RESET_ALL}")

    # Verdict
    print(f"\n{Style.BRIGHT}  RISK SCORE{Style.RESET_ALL}")
    print(_line())
    print(f"  Score      : {score}/100   {_bar(score)}")
    print(f"  Confidence : {risk.get('confidence','?')}")
    print(f"\n  {vc}  {risk['verdict']} — {score}/100  {Style.RESET_ALL}")
    print(f"\n  {risk['label']}")

    # Recommendations
    print(f"\n{Style.BRIGHT}  SECURITY RECOMMENDATIONS{Style.RESET_ALL}")
    print(_line())
    _recommendations(results, risk)
    print(_line("═") + "\n")


def _recommendations(results, risk):
    recs = []
    if not results["spf"].get("found"):
        recs.append("Domain has no SPF record — admin should publish one to prevent spoofing.")
    if not results["dmarc"].get("found"):
        recs.append("No DMARC policy — email receivers cannot enforce authentication failures.")
    if not results["dkim"].get("found"):
        recs.append("Email is unsigned (no DKIM) — integrity of headers cannot be verified.")
    if results.get("spoofing"):
        recs.append("Header anomalies detected — do NOT reply to this email address.")
    if results.get("url_threats"):
        recs.append("Suspicious URLs found — do NOT click. Check links at virustotal.com first.")
    if results.get("keywords"):
        recs.append("Phishing language detected — do NOT provide credentials or financial info.")
    if risk["verdict"] == "HIGH RISK":
        recs.append("Report immediately to your IT/security team.")
        recs.append("Delete the email. Do not forward it to others.")
    if not recs:
        recs.append("No immediate action required. Always be cautious with unsolicited emails.")
    for i, r in enumerate(recs, 1):
        print(f"  {i}. {r}")


def save_report(results: dict, out_dir: str = ".") -> str:
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = os.path.join(out_dir, f"phishing_report_{timestamp}.txt")
    h    = results["headers"]
    risk = results["risk"]

    lines = [
        "="*70,
        "  EMAIL PHISHING ANALYSIS REPORT  v2.0",
        f"  Generated : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "="*70, "",
        "EMAIL METADATA", "-"*40,
        f"  From          : {h.get('from','—')}",
        f"  Reply-To      : {h.get('reply_to','—')}",
        f"  Subject       : {h.get('subject','—')}",
        f"  Sender Domain : {h.get('sender_domain','—')}",
        "", "DNS AUTHENTICATION", "-"*40,
        f"  SPF   : {'FOUND' if results['spf'].get('found') else 'NOT FOUND'}  — {results['spf'].get('detail','')}",
        f"  DMARC : {'FOUND' if results['dmarc'].get('found') else 'NOT FOUND'}  — {results['dmarc'].get('detail','')}",
        f"  DKIM  : {'PRESENT' if results['dkim'].get('found') else 'NOT PRESENT'}  — {results['dkim'].get('detail','')}",
        "", "CATEGORY SCORES", "-"*40,
    ]
    for cat, pts in risk.get("category_scores",{}).items():
        lines.append(f"  {cat:<25}: {pts} pts")

    lines += [
        "", "RISK ASSESSMENT", "-"*40,
        f"  Score      : {risk['display_score']}/100",
        f"  Verdict    : {risk['verdict']}",
        f"  Confidence : {risk.get('confidence','?')}",
        f"  {risk['label']}",
        "", "SCORE BREAKDOWN", "-"*40,
    ]
    for item in risk["breakdown"]:
        lines.append(f"  +{item['pts']:>3} pts  [{item.get('category',''):<12}]  [{item['severity']:<6}]  {item['check']}")

    lines += ["", "="*70]
    with open(filename,"w",encoding="utf-8") as f:
        f.write("\n".join(lines))
    return filename
