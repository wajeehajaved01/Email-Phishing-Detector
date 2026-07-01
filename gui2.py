"""
gui.py — PRODUCTION GUI v2.1
Email Phishing Detection System
Tkinter UI — gold-on-forest theme, non-blocking DNS, upgraded analyzers.
Run: python gui.py
"""

import tkinter as tk
from tkinter import filedialog, scrolledtext
import threading, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzers.email_parser     import parse_email
from analyzers.header_analyzer  import check_spoofing
from analyzers.dns_checker      import check_all_dns_parallel, check_dkim_header
from analyzers.keyword_analyzer import scan_keywords
from analyzers.url_threat       import analyse_urls
from scoring.risk_engine        import calculate_risk

# ── Palette: Deep Forest + Gold ──────────────────────────────────────────────
BG        = "#0f1d17"
PANEL     = "#16291f"
PANEL_ALT = "#1d3528"
BORDER    = "#2d4a3a"

GOLD    = "#f5c542"
GOLD_HI = "#ffd966"
EMERALD = "#3fd17a"
AMBER   = "#f0a830"
CRIMSON = "#ef5350"

TEXT = "#f4ead5"
MUTED = "#a8b8ad"
DIM   = "#7a8a80"
RULE  = "#2a4435"

F_BODY = ("Segoe UI", 10)
F_MONO = ("Consolas", 10)
F_HEAD = ("Segoe UI Semibold", 11)
F_BIG  = ("Segoe UI Semibold", 14)
F_HUGE = ("Segoe UI", 40, "bold")


# ── Analysis pipeline ────────────────────────────────────────────────────────
def run_analysis(raw: str, vt_key: str = "") -> dict:
    headers     = parse_email(raw)
    domain      = headers.get("sender_domain", "")
    spf, dmarc  = check_all_dns_parallel(domain)
    dkim        = check_dkim_header(headers.get("dkim_signature", ""))
    spoof       = check_spoofing(headers)
    kw          = scan_keywords(headers.get("body", ""))
    url_threats = analyse_urls(headers.get("body", ""), vt_key)
    results = {
        "headers": headers, "spf": spf, "dmarc": dmarc, "dkim": dkim,
        "spoofing": spoof, "keywords": kw,
        "url_threats": url_threats, "urls": [],
    }
    results["risk"] = calculate_risk(results)
    return results


# ── Reusable widgets ─────────────────────────────────────────────────────────
class Card(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=PANEL,
                         highlightthickness=1, highlightbackground=BORDER, **kw)


class HoverButton(tk.Button):
    def __init__(self, parent, hover_bg, base_bg, **kw):
        super().__init__(parent, bg=base_bg, **kw)
        self._b, self._h = base_bg, hover_bg
        self.bind("<Enter>", lambda e: self.configure(bg=self._h))
        self.bind("<Leave>", lambda e: self.configure(bg=self._b))


# ── Main application ─────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PhishGuard v2.1  |  Email Phishing Detection  |  IS Lab  |  UET Lahore")
        self.geometry("1200x820")
        self.minsize(1080, 720)
        self.configure(bg=BG)
        self._build()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build(self):
        # Top bar
        hdr = tk.Frame(self, bg=PANEL, height=58)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        brand = tk.Frame(hdr, bg=PANEL)
        brand.pack(side="left", padx=22, pady=10)
        tk.Label(brand, text="✦", font=("Segoe UI", 18, "bold"),
                 bg=PANEL, fg=GOLD).pack(side="left", padx=(0, 10))
        tk.Label(brand, text="PHISHGUARD",
                 font=("Segoe UI", 14, "bold"), bg=PANEL, fg=TEXT).pack(side="left")
        tk.Label(brand, text="  v2.1",
                 font=("Segoe UI", 10), bg=PANEL, fg=GOLD).pack(side="left")
        tk.Label(hdr, text="Async DNS  ·  Threat Intel  ·  MIME Parser",
                 font=F_BODY, bg=PANEL, fg=MUTED).pack(side="right", padx=22)

        tk.Frame(self, bg=GOLD, height=2).pack(fill="x")

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=18, pady=14)
        self._build_left(body)
        self._build_right(body)

    def _build_left(self, parent):
        lf = tk.Frame(parent, bg=BG)
        lf.pack(side="left", fill="both", expand=True, padx=(0, 9))

        self._sec(lf, "EMAIL INPUT", "✉")

        # VirusTotal API key
        api = Card(lf)
        api.pack(fill="x", pady=(0, 10))
        api_in = tk.Frame(api, bg=PANEL)
        api_in.pack(fill="x", padx=12, pady=10)
        tk.Label(api_in, text="VirusTotal API Key",
                 font=F_BODY, bg=PANEL, fg=MUTED).pack(side="left")
        tk.Label(api_in, text="  optional",
                 font=("Segoe UI", 8, "italic"), bg=PANEL, fg=DIM).pack(side="left")
        self.vt_entry = tk.Entry(
            api_in, font=F_MONO, bg=PANEL_ALT, fg=TEXT,
            insertbackground=GOLD, relief="flat",
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=GOLD)
        self.vt_entry.pack(side="left", fill="x", expand=True, padx=(12, 0), ipady=4)

        # Demo buttons
        btns = tk.Frame(lf, bg=BG)
        btns.pack(fill="x", pady=(0, 10))
        self._chip(btns, "📂  Load .eml",
                   self._load_file).pack(side="left", padx=(0, 6))
        self._chip(btns, "● Phishing",
                   lambda: self._demo("phishing_paypal.eml"),
                   fg=CRIMSON).pack(side="left", padx=(0, 6))
        self._chip(btns, "● Suspicious",
                   lambda: self._demo("suspicious_medium.eml"),
                   fg=AMBER).pack(side="left", padx=(0, 6))
        self._chip(btns, "● Legitimate",
                   lambda: self._demo("legitimate_github.eml"),
                   fg=EMERALD).pack(side="left")

        # Email text area
        box_wrap = Card(lf)
        box_wrap.pack(fill="both", expand=True)
        self.email_box = scrolledtext.ScrolledText(
            box_wrap, font=F_MONO, bg=PANEL, fg=MUTED,
            insertbackground=GOLD, relief="flat", borderwidth=0,
            wrap="word", height=20, padx=12, pady=12)
        self.email_box.pack(fill="both", expand=True, padx=1, pady=1)

        HINT = "Paste raw email content here, or click a demo button above…"
        self.email_box.insert("1.0", HINT)

        def _clear(e):
            if self.email_box.get("1.0", "end-1c") == HINT:
                self.email_box.delete("1.0", "end")
                self.email_box.configure(fg=TEXT)
        self.email_box.bind("<FocusIn>", _clear)

        # Status bar
        self.status_var = tk.StringVar(value="● Ready")
        tk.Label(lf, textvariable=self.status_var,
                 font=("Segoe UI", 9), bg=BG, fg=MUTED,
                 anchor="w").pack(fill="x", pady=(8, 0))

        # Analyze button
        self.btn_analyze = HoverButton(
            lf, hover_bg=GOLD_HI, base_bg=GOLD,
            text="ANALYZE EMAIL   ▶",
            font=("Segoe UI", 12, "bold"),
            fg="#1a1a1a", activebackground=GOLD_HI, activeforeground="#1a1a1a",
            relief="flat", cursor="hand2", pady=14, borderwidth=0,
            command=self._start)
        self.btn_analyze.pack(fill="x", pady=(10, 0))

    def _build_right(self, parent):
        rf = tk.Frame(parent, bg=BG, width=480)
        rf.pack(side="right", fill="both", padx=(9, 0))
        rf.pack_propagate(False)

        self._sec(rf, "ANALYSIS RESULTS", "▣")

        # Verdict card
        self.vf = tk.Frame(rf, bg=PANEL, pady=18,
                           highlightthickness=2, highlightbackground=BORDER)
        self.vf.pack(fill="x", pady=(0, 10))
        self.v_score = tk.Label(self.vf, text="—",
                                font=F_HUGE, bg=PANEL, fg=DIM)
        self.v_score.pack()
        tk.Label(self.vf, text="RISK SCORE  /  100",
                 font=("Segoe UI", 8), bg=PANEL, fg=DIM).pack()
        self.v_label = tk.Label(self.vf, text="Awaiting analysis",
                                font=F_BIG, bg=PANEL, fg=MUTED)
        self.v_label.pack(pady=(8, 0))
        self.v_conf = tk.Label(self.vf, text="",
                               font=F_BODY, bg=PANEL, fg=MUTED)
        self.v_conf.pack(pady=(4, 0))

        # Score bar
        self.bar_canvas = tk.Canvas(rf, height=10, bg=PANEL,
                                    highlightthickness=1, highlightbackground=BORDER)
        self.bar_canvas.pack(fill="x", pady=(0, 12))

        # Category scores
        self._sec(rf, "CATEGORY SCORES", "▦")
        cat_frame = Card(rf)
        cat_frame.pack(fill="x", pady=(0, 10))
        self.cat_labels = {}
        cats = ["DNS Authentication", "Header Spoofing",
                "URL / Threats", "Keywords", "Extras"]
        for i, c in enumerate(cats):
            row = tk.Frame(cat_frame, bg=PANEL)
            top_pad = 8 if i == 0 else 4
            bot_pad = 8 if i == len(cats) - 1 else 4
            row.pack(fill="x", padx=14, pady=(top_pad, bot_pad))
            tk.Label(row, text=c, font=F_BODY, bg=PANEL, fg=TEXT).pack(side="left")
            lbl = tk.Label(row, text="—",
                           font=("Consolas", 10, "bold"), bg=PANEL, fg=DIM)
            lbl.pack(side="right")
            self.cat_labels[c] = lbl

        # DNS authentication
        self._sec(rf, "DNS AUTHENTICATION", "⚿")
        dns_f = Card(rf)
        dns_f.pack(fill="x", pady=(0, 10))
        self.spf_lbl   = self._auth_row(dns_f, "SPF")
        self.dmarc_lbl = self._auth_row(dns_f, "DMARC")
        self.dkim_lbl  = self._auth_row(dns_f, "DKIM")

        # Detailed breakdown
        self._sec(rf, "DETAILED BREAKDOWN", "≡")
        detail_wrap = Card(rf)
        detail_wrap.pack(fill="both", expand=True)
        self.detail = scrolledtext.ScrolledText(
            detail_wrap, font=F_MONO, bg=PANEL, fg=TEXT,
            insertbackground=GOLD, relief="flat", borderwidth=0,
            selectbackground="#2f5742",
            state="disabled", wrap="word", height=12,
            padx=14, pady=12)
        self.detail.pack(fill="both", expand=True, padx=1, pady=1)

        # Text tags
        self.detail.tag_configure("head",   foreground=GOLD,    font=("Segoe UI Semibold", 11), spacing1=6, spacing3=2)
        self.detail.tag_configure("rule",   foreground=RULE)
        self.detail.tag_configure("text",   foreground=TEXT)
        self.detail.tag_configure("dim",    foreground=DIM)
        self.detail.tag_configure("gold",   foreground=GOLD)
        self.detail.tag_configure("accent", foreground=EMERALD)
        self.detail.tag_configure("ok",     foreground=EMERALD, font=("Segoe UI Semibold", 10))
        self.detail.tag_configure("high",   foreground=CRIMSON, font=("Segoe UI Semibold", 10))
        self.detail.tag_configure("med",    foreground=AMBER,   font=("Segoe UI Semibold", 10))
        self.detail.tag_configure("low",    foreground=GOLD,    font=("Segoe UI Semibold", 10))

    # ── Helper widgets ────────────────────────────────────────────────────────

    def _sec(self, parent, text, icon=""):
        f = tk.Frame(parent, bg=BG)
        f.pack(fill="x", pady=(2, 8))
        if icon:
            tk.Label(f, text=icon, font=("Segoe UI", 11),
                     bg=BG, fg=GOLD).pack(side="left", padx=(0, 6))
        tk.Label(f, text=text, font=F_HEAD,
                 bg=BG, fg=TEXT).pack(side="left")
        tk.Frame(f, bg=BORDER, height=1).pack(
            side="left", fill="x", expand=True, padx=(12, 0), pady=8)

    def _chip(self, parent, text, cmd, fg=None):
        b = HoverButton(
            parent, hover_bg=PANEL_ALT, base_bg=PANEL,
            text=text, font=("Segoe UI", 9),
            fg=fg or TEXT,
            activebackground=PANEL_ALT, activeforeground=fg or TEXT,
            relief="flat", cursor="hand2", padx=12, pady=7,
            highlightthickness=1, highlightbackground=BORDER,
            borderwidth=0, command=cmd)
        return b

    def _auth_row(self, parent, label):
        row = tk.Frame(parent, bg=PANEL)
        row.pack(fill="x", padx=14, pady=8)
        tk.Label(row, text=label, font=("Segoe UI Semibold", 10),
                 bg=PANEL, fg=GOLD, width=7, anchor="w").pack(side="left")
        lbl = tk.Label(row, text="—", font=F_MONO, bg=PANEL, fg=DIM, anchor="w")
        lbl.pack(side="left", fill="x", expand=True)
        return lbl

    # ── Actions ───────────────────────────────────────────────────────────────

    def _load_file(self):
        path = filedialog.askopenfilename(
            filetypes=[("Email files", "*.eml"), ("All files", "*.*")])
        if path:
            with open(path, "r", errors="replace") as f:
                self._set_text(f.read())

    def _demo(self, fname):
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "samples", fname)
        if not os.path.exists(path):
            self.status_var.set(f"⚠ Demo file not found: {path}")
            return
        with open(path, "r", errors="replace") as f:
            self._set_text(f.read())

    def _set_text(self, text):
        self.email_box.configure(fg=TEXT)
        self.email_box.delete("1.0", "end")
        self.email_box.insert("1.0", text)

    def _start(self):
        raw = self.email_box.get("1.0", "end-1c").strip()
        if not raw or raw.startswith("Paste raw email"):
            self.status_var.set("⚠ Please load or paste an email first.")
            return
        vt = self.vt_entry.get().strip()
        self.btn_analyze.configure(text="⏳  ANALYZING…", state="disabled")
        self.status_var.set("● Running DNS lookups in background threads…")
        threading.Thread(target=self._analyze, args=(raw, vt), daemon=True).start()

    def _analyze(self, raw, vt_key):
        try:
            res = run_analysis(raw, vt_key)
            self.after(0, self._show, res)
        except Exception as e:
            self.after(0, self.status_var.set, f"✘ Error: {e}")
        finally:
            self.after(0, lambda: self.btn_analyze.configure(
                text="ANALYZE EMAIL   ▶", state="normal"))

    # ── Render results ────────────────────────────────────────────────────────

    def _show(self, r):
        risk  = r["risk"]
        score = risk["display_score"]
        vc    = {"RED": CRIMSON, "YELLOW": AMBER, "GREEN": EMERALD}.get(
            risk["color"], GOLD)

        # Verdict card
        self.vf.configure(highlightbackground=vc)
        self.v_score.configure(text=str(score), fg=vc)
        self.v_label.configure(text=risk["verdict"].upper(), fg=vc)
        self.v_conf.configure(
            text=f"Confidence: {risk.get('confidence','?')}   ·   {risk['label']}",
            fg=MUTED)

        # Score bar
        self.bar_canvas.update_idletasks()
        w = self.bar_canvas.winfo_width()
        self.bar_canvas.delete("all")
        filled = int((score / 100) * w)
        self.bar_canvas.create_rectangle(0, 0, w, 10, fill=PANEL_ALT, outline="")
        self.bar_canvas.create_rectangle(0, 0, filled, 10, fill=vc, outline="")

        # Category scores
        cat_scores = risk.get("category_scores", {})
        for cname, lbl in self.cat_labels.items():
            pts   = cat_scores.get(cname, 0)
            color = (CRIMSON if pts >= 15 else
                     AMBER   if pts >= 5  else
                     EMERALD if pts == 0  else GOLD)
            lbl.configure(text=f"{pts} pts", fg=color)

        # DNS rows
        def _dns_lbl(d, lbl):
            v = d.get("found")
            if v is True:    t, c = "✓  FOUND",       EMERALD
            elif v is False: t, c = "✘  NOT FOUND",   CRIMSON
            else:            t, c = "?  UNKNOWN",      AMBER
            lbl.configure(text=f"{t}   {d.get('detail','')[:50]}", fg=c)

        _dns_lbl(r["spf"],   self.spf_lbl)
        _dns_lbl(r["dmarc"], self.dmarc_lbl)

        dk = r["dkim"]
        if dk.get("found"):
            dkt = "✓  PRESENT" if dk.get("valid_structure") else "⚠  MALFORMED"
            dkc = EMERALD if dk.get("valid_structure") else AMBER
        else:
            dkt, dkc = "✘  NOT PRESENT", CRIMSON
        self.dkim_lbl.configure(
            text=f"{dkt}   {dk.get('detail','')[:40]}", fg=dkc)

        # Detailed breakdown
        self._render_details(r, risk, score)

    def _render_details(self, r, risk, score):
        db = self.detail
        db.configure(state="normal")
        db.delete("1.0", "end")
        h = r["headers"]

        def w(text, tag="text"):
            db.insert("end", text, tag)

        def section(title, count=None):
            count_str = f"  ({count})" if count is not None else ""
            w(f"\n✦  {title}{count_str}\n", "head")
            w("   " + "─" * 54 + "\n", "rule")

        def kv(label, value, tag="text"):
            w(f"   {label:<13}", "dim")
            w(f"{value}\n", tag)

        def sev_tag(sev):
            return {"HIGH": "high", "MEDIUM": "med", "LOW": "low"}.get(sev, "dim")

        # ── Metadata ──────────────────────────────────────────────
        section("METADATA")
        kv("From",       h.get("from",          "—"))
        kv("Reply-To",   h.get("reply_to",       "—"))
        kv("Subject",    h.get("subject",        "—"), "gold")
        kv("Domain",     h.get("sender_domain",  "—"), "accent")

        atts = h.get("attachments", [])
        kv("Attachments", f"{len(atts)} found" if atts else "none",
           "med" if atts else "ok")
        for a in atts:
            w(f"      • {a['filename']}", "text")
            w(f"  ({a['type']}, {a['size_bytes']} B)\n", "dim")

        pixels = h.get("tracking_pixels", [])
        if pixels:
            kv("Tracking px", f"{len(pixels)} detected", "med")

        # ── Header flags ───────────────────────────────────────────
        flags = r.get("spoofing", [])
        section("HEADER FLAGS", len(flags))
        if not flags:
            w("   ● No anomalies detected.\n", "ok")
        else:
            for f in flags:
                tag = sev_tag(f["severity"])
                w(f"   [{f['severity']:<6}]", tag)
                w(f"  {f['check']}\n", "text")
                w(f"               {f['detail']}\n", "dim")

        # ── URL threats ────────────────────────────────────────────
        uts = r.get("url_threats", [])
        section("URL THREAT ANALYSIS", f"{len(uts)} suspicious")
        if not uts:
            w("   ● No suspicious URLs detected.\n", "ok")
        else:
            for ut in uts:
                tag = sev_tag(ut["severity"])
                w(f"   [{ut['severity']:<6}]", tag)
                w(f"  {ut['domain']}\n", "accent")
                w(f"               {ut['summary'][:88]}\n", "dim")

        # ── Keywords ───────────────────────────────────────────────
        kws = r.get("keywords", [])
        section("PHISHING KEYWORDS", len(kws))
        if not kws:
            w("   ● None found.\n", "ok")
        else:
            for k in kws:
                tag = sev_tag(k["severity"])
                w(f"   [{k['severity']:<6}]", tag)
                w(f"  \u201c{k['keyword']}\u201d\n", "text")

        # ── Score breakdown ────────────────────────────────────────
        section("SCORE BREAKDOWN")
        for item in risk["breakdown"]:
            tag = sev_tag(item.get("severity", ""))
            cat = item.get("category", "")
            w(f"   +{item['pts']:>3} pts", "gold")
            w(f"  [{cat:<12}]", "dim")
            w(f"  {item['check']}\n", tag)

        db.configure(state="disabled")
        self.status_var.set(
            f"●  Analysis complete   ·   {score}/100   ·   {risk['verdict']}")


if __name__ == "__main__":
    App().mainloop()