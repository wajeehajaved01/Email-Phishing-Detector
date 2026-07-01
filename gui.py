"""
gui.py  —  PRODUCTION GUI  v2.0
Email Phishing Detection System
Tkinter UI — non-blocking DNS via threads, upgraded analyzers.
Run: python gui.py
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import threading, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzers.email_parser     import parse_email
from analyzers.header_analyzer  import check_spoofing
from analyzers.dns_checker      import check_all_dns_parallel, check_dkim_header
from analyzers.keyword_analyzer import scan_keywords
from analyzers.url_threat       import analyse_urls
from scoring.risk_engine        import calculate_risk

# ── Palette ──────────────────────────────────────────────────────────────────
BG, PANEL, BORDER = "#0d1117", "#161b22", "#30363d"
ACCENT = "#58a6ff"
GREEN, YELLOW, RED = "#3fb950", "#d29922", "#f85149"
TEXT, MUTED = "#e6edf3", "#8b949e"
F_MAIN = ("Consolas", 10)
F_HEAD = ("Consolas", 11, "bold")
F_BIG  = ("Consolas", 13, "bold")


def run_analysis(raw: str, vt_key: str = "") -> dict:
    headers     = parse_email(raw)
    domain      = headers.get("sender_domain", "")
    spf, dmarc  = check_all_dns_parallel(domain)   # parallel DNS
    dkim        = check_dkim_header(headers.get("dkim_signature", ""))
    spoof       = check_spoofing(headers)
    kw          = scan_keywords(headers.get("body", ""))
    url_threats = analyse_urls(headers.get("body", ""), vt_key)
    results = {
        "headers": headers, "spf": spf, "dmarc": dmarc, "dkim": dkim,
        "spoofing": spoof, "keywords": kw, "url_threats": url_threats, "urls": [],
    }
    results["risk"] = calculate_risk(results)
    return results


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("📧 Email Phishing Detection System v2.0  |  IS Lab Project  |  UET Lahore")
        self.geometry("1150x800")
        self.configure(bg=BG)
        self._build()

    # ── Build UI ─────────────────────────────────────────────────────────────
    def _build(self):
        # Header
        hdr = tk.Frame(self, bg=PANEL, height=52)
        hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr, text="📧  EMAIL PHISHING DETECTION SYSTEM  v2.0",
                 font=("Consolas", 13, "bold"), bg=PANEL, fg=ACCENT).pack(side="left", padx=20, pady=12)
        tk.Label(hdr, text="Async DNS  |  Threat Intelligence  |  MIME Parser",
                 font=F_MAIN, bg=PANEL, fg=MUTED).pack(side="right", padx=20)
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # Body — split left/right
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=14, pady=10)

        self._build_left(body)
        self._build_right(body)

    def _build_left(self, parent):
        lf = tk.Frame(parent, bg=BG)
        lf.pack(side="left", fill="both", expand=True)

        self._sec(lf, "📨  EMAIL INPUT")

        # API key row
        api_row = tk.Frame(lf, bg=BG)
        api_row.pack(fill="x", pady=(0, 6))
        tk.Label(api_row, text="VirusTotal API Key (optional):",
                 font=F_MAIN, bg=BG, fg=MUTED).pack(side="left")
        self.vt_entry = tk.Entry(api_row, font=F_MAIN, bg=PANEL, fg=TEXT,
                                  insertbackground=ACCENT, relief="flat",
                                  highlightthickness=1, highlightbackground=BORDER, width=36)
        self.vt_entry.pack(side="left", padx=(8, 0))
        tk.Label(api_row, text="free at virustotal.com",
                 font=("Consolas", 8), bg=BG, fg=MUTED).pack(side="left", padx=6)

        # Demo buttons
        btn_row = tk.Frame(lf, bg=BG)
        btn_row.pack(fill="x", pady=(0, 6))
        self._btn(btn_row, "📂 Load .eml",           self._load_file).pack(side="left", padx=(0, 6))
        self._btn(btn_row, "🔴 Demo: Phishing",      lambda: self._demo("phishing_paypal.eml")).pack(side="left", padx=(0, 6))
        self._btn(btn_row, "🟡 Demo: Suspicious",    lambda: self._demo("suspicious_medium.eml")).pack(side="left", padx=(0, 6))
        self._btn(btn_row, "🟢 Demo: Legitimate",    lambda: self._demo("legitimate_github.eml")).pack(side="left")

        # Email text area
        self.email_box = scrolledtext.ScrolledText(
            lf, font=("Consolas", 9), bg=PANEL, fg=MUTED,
            insertbackground=ACCENT, relief="flat",
            highlightthickness=1, highlightbackground=BORDER, wrap="word", height=20)
        self.email_box.pack(fill="both", expand=True)
        HINT = "Paste raw email content here, or click a demo button above..."
        self.email_box.insert("1.0", HINT)

        def _clear(e):
            if self.email_box.get("1.0","end-1c") == HINT:
                self.email_box.delete("1.0","end")
                self.email_box.configure(fg=TEXT)
        self.email_box.bind("<FocusIn>", _clear)

        # Status bar
        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(lf, textvariable=self.status_var, font=("Consolas", 9),
                 bg=BG, fg=MUTED, anchor="w").pack(fill="x", pady=(4,0))

        # Analyze button
        self.btn_analyze = tk.Button(
            lf, text="🔍  ANALYZE EMAIL",
            font=("Consolas", 12, "bold"), bg=ACCENT, fg=BG,
            activebackground="#79c0ff", relief="flat", cursor="hand2", pady=10,
            command=self._start)
        self.btn_analyze.pack(fill="x", pady=(8, 0))

    def _build_right(self, parent):
        rf = tk.Frame(parent, bg=BG, width=460)
        rf.pack(side="right", fill="both", padx=(14, 0))
        rf.pack_propagate(False)

        self._sec(rf, "📊  ANALYSIS RESULTS")

        # Verdict card
        self.vf = tk.Frame(rf, bg=PANEL, pady=12,
                            highlightthickness=2, highlightbackground=BORDER)
        self.vf.pack(fill="x", pady=(0, 8))
        self.v_score = tk.Label(self.vf, text="—",
                                font=("Consolas", 36, "bold"), bg=PANEL, fg=MUTED)
        self.v_score.pack()
        self.v_label = tk.Label(self.vf, text="Run analysis to see verdict",
                                font=F_BIG, bg=PANEL, fg=MUTED)
        self.v_label.pack()
        self.v_conf  = tk.Label(self.vf, text="",
                                font=F_MAIN, bg=PANEL, fg=MUTED)
        self.v_conf.pack(pady=(2,0))

        # Score bar
        self.bar_canvas = tk.Canvas(rf, height=20, bg=PANEL,
                                    highlightthickness=0)
        self.bar_canvas.pack(fill="x", pady=(0,8))

        # Category breakdown mini-table
        self._sec(rf, "📂  CATEGORY SCORES")
        cat_frame = tk.Frame(rf, bg=PANEL,
                              highlightthickness=1, highlightbackground=BORDER)
        cat_frame.pack(fill="x", pady=(0, 8))
        self.cat_labels = {}
        cats = ["DNS Authentication", "Header Spoofing", "URL / Threats",
                "Keywords", "Extras"]
        for c in cats:
            row = tk.Frame(cat_frame, bg=PANEL)
            row.pack(fill="x", padx=10, pady=3)
            tk.Label(row, text=f"{c:<22}", font=F_MAIN, bg=PANEL, fg=MUTED).pack(side="left")
            lbl = tk.Label(row, text="—", font=F_MAIN, bg=PANEL, fg=MUTED)
            lbl.pack(side="left")
            self.cat_labels[c] = lbl

        # DNS auth row
        self._sec(rf, "🔐  DNS AUTHENTICATION")
        dns_f = tk.Frame(rf, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        dns_f.pack(fill="x", pady=(0, 8))
        self.spf_lbl   = self._auth_row(dns_f, "SPF  ")
        self.dmarc_lbl = self._auth_row(dns_f, "DMARC")
        self.dkim_lbl  = self._auth_row(dns_f, "DKIM ")

        # Detail box
        self._sec(rf, "🔎  DETAILED FLAGS & BREAKDOWN")
        self.detail = scrolledtext.ScrolledText(
            rf, font=("Consolas", 9), bg=PANEL, fg=TEXT,
            relief="flat", highlightthickness=1, highlightbackground=BORDER,
            state="disabled", wrap="word", height=14)
        self.detail.pack(fill="both", expand=True)
        for tag, fg in [("high",RED),("med",YELLOW),("low",ACCENT),
                        ("ok",GREEN),("head",MUTED),("dim",MUTED)]:
            self.detail.tag_config(tag, foreground=fg)
        self.detail.tag_config("head", font=("Consolas", 9, "bold"))

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _sec(self, p, text):
        f = tk.Frame(p, bg=BG); f.pack(fill="x", pady=(0,5))
        tk.Label(f, text=text, font=F_HEAD, bg=BG, fg=MUTED).pack(side="left")
        tk.Frame(f, bg=BORDER, height=1).pack(side="left", fill="x",
                                               expand=True, padx=(8,0), pady=6)

    def _btn(self, p, txt, cmd):
        return tk.Button(p, text=txt, font=("Consolas", 9), bg=PANEL, fg=TEXT,
                         activebackground=BORDER, relief="flat", cursor="hand2",
                         padx=10, pady=5, command=cmd,
                         highlightthickness=1, highlightbackground=BORDER)

    def _auth_row(self, p, label):
        row = tk.Frame(p, bg=PANEL); row.pack(fill="x", padx=10, pady=4)
        tk.Label(row, text=label, font=F_MAIN, bg=PANEL, fg=MUTED).pack(side="left")
        lbl = tk.Label(row, text="—", font=F_MAIN, bg=PANEL, fg=MUTED)
        lbl.pack(side="left"); return lbl

    # ── Actions ───────────────────────────────────────────────────────────────
    def _load_file(self):
        p = filedialog.askopenfilename(filetypes=[("Email","*.eml"),("All","*.*")])
        if p:
            with open(p, "r", errors="replace") as f:
                self._set_text(f.read())

    def _demo(self, fname):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples", fname)
        if not os.path.exists(path):
            self.status_var.set(f"Demo file not found: {path}")
            return
        with open(path, "r", errors="replace") as f:
            self._set_text(f.read())

    def _set_text(self, text):
        self.email_box.configure(fg=TEXT)
        self.email_box.delete("1.0","end")
        self.email_box.insert("1.0", text)

    def _start(self):
        raw = self.email_box.get("1.0","end-1c").strip()
        if not raw or "Paste raw email" in raw:
            self.status_var.set("⚠ Please load or paste an email first.")
            return
        vt  = self.vt_entry.get().strip()
        self.btn_analyze.configure(text="⏳  Analyzing (DNS running)...", state="disabled")
        self.status_var.set("Running DNS lookups in background threads...")
        threading.Thread(target=self._analyze, args=(raw, vt), daemon=True).start()

    def _analyze(self, raw, vt_key):
        try:
            res = run_analysis(raw, vt_key)
            self.after(0, self._show, res)
        except Exception as e:
            self.after(0, self.status_var.set, f"Error: {e}")
        finally:
            self.after(0, lambda: self.btn_analyze.configure(
                text="🔍  ANALYZE EMAIL", state="normal"))

    # ── Render results ────────────────────────────────────────────────────────
    def _show(self, r):
        risk  = r["risk"]
        score = risk["display_score"]
        vc    = {"RED": RED, "YELLOW": YELLOW, "GREEN": GREEN}.get(risk["color"], MUTED)

        # Verdict card
        self.vf.configure(highlightbackground=vc)
        self.v_score.configure(text=f"{score}/100", fg=vc)
        self.v_label.configure(text=risk["verdict"], fg=vc)
        conf = risk.get("confidence","?")
        self.v_conf.configure(text=f"Detection Confidence: {conf}  |  {risk['label']}", fg=MUTED)

        # Score bar
        self.bar_canvas.update_idletasks()
        w = self.bar_canvas.winfo_width()
        self.bar_canvas.delete("all")
        filled = int((score / 100) * w)
        self.bar_canvas.create_rectangle(0,0,w,20, fill=PANEL, outline="")
        self.bar_canvas.create_rectangle(0,0,filled,20, fill=vc, outline="")
        self.bar_canvas.create_text(w//2, 10, text=f"{score}/100",
                                    fill=TEXT, font=("Consolas",9,"bold"))

        # Category scores
        cat_scores = risk.get("category_scores", {})
        for cname, lbl in self.cat_labels.items():
            pts = cat_scores.get(cname, 0)
            color = RED if pts >= 15 else YELLOW if pts >= 5 else GREEN if pts == 0 else MUTED
            lbl.configure(text=f"{pts:>3} pts", fg=color)

        # DNS
        def _dns_lbl(d, lbl):
            v = d.get("found")
            if v is True:   t, c = "✔ FOUND    ", GREEN
            elif v is False: t, c = "✘ NOT FOUND", RED
            else:            t, c = "? UNKNOWN  ", YELLOW
            detail = d.get("detail","")[:52]
            lbl.configure(text=f"{t}  {detail}", fg=c)
        _dns_lbl(r["spf"],   self.spf_lbl)
        _dns_lbl(r["dmarc"], self.dmarc_lbl)
        dk = r["dkim"]
        if dk.get("found"):
            dkt = "✔ PRESENT  " if dk.get("valid_structure") else "⚠ MALFORMED"
            dkc = GREEN if dk.get("valid_structure") else YELLOW
        else:
            dkt, dkc = "✘ NOT PRESENT", RED
        self.dkim_lbl.configure(text=f"{dkt}  {dk.get('detail','')[:40]}", fg=dkc)

        # Detail box
        db = self.detail
        db.configure(state="normal"); db.delete("1.0","end")
        h = r["headers"]

        def w(text, tag=""):
            db.insert("end", text, tag)

        w("── METADATA ───────────────────────────────────────\n","head")
        w(f"  From       : {h.get('from','—')}\n")
        w(f"  Reply-To   : {h.get('reply_to','—')}\n")
        w(f"  Subject    : {h.get('subject','—')}\n")
        w(f"  Domain     : {h.get('sender_domain','—')}\n")
        atts = h.get("attachments",[])
        if atts:
            w(f"  Attachments: {len(atts)} found\n","med")
            for a in atts:
                w(f"    • {a['filename']} ({a['type']}, {a['size_bytes']}B)\n","dim")
        pixels = h.get("tracking_pixels",[])
        if pixels:
            w(f"  Tracking pixels: {len(pixels)} detected\n","med")

        # Spoofing
        flags = r.get("spoofing",[])
        w(f"\n── HEADER FLAGS ({len(flags)}) ────────────────────────────\n","head")
        if not flags:
            w("  No anomalies detected.\n","ok")
        else:
            for f in flags:
                tag = {"HIGH":"high","MEDIUM":"med","LOW":"low"}.get(f["severity"],"low")
                w(f"  [{f['severity']:<6}] {f['check']}\n",tag)
                w(f"           {f['detail']}\n","dim")

        # URL threats
        uts = r.get("url_threats",[])
        w(f"\n── URL THREAT ANALYSIS ({len(uts)} suspicious) ──────────\n","head")
        if not uts:
            w("  No suspicious URLs detected.\n","ok")
        else:
            for ut in uts:
                w(f"  [{ut['severity']:<6}] {ut['domain']}\n",
                  {"HIGH":"high","MEDIUM":"med","LOW":"low"}.get(ut["severity"],"low"))
                w(f"           {ut['summary'][:90]}\n","dim")

        # Keywords
        kws = r.get("keywords",[])
        w(f"\n── PHISHING KEYWORDS ({len(kws)}) ─────────────────────────\n","head")
        if not kws:
            w("  None found.\n","ok")
        else:
            for k in kws:
                tag = {"HIGH":"high","MEDIUM":"med","LOW":"low"}.get(k["severity"],"low")
                w(f"  [{k['severity']:<6}] \"{k['keyword']}\"\n",tag)

        # Score breakdown
        w("\n── SCORE BREAKDOWN ─────────────────────────────────\n","head")
        for item in risk["breakdown"]:
            tag = {"HIGH":"high","MEDIUM":"med","LOW":"low"}.get(item.get("severity",""),"dim")
            cat = item.get("category","")
            w(f"  +{item['pts']:>3} pts  [{cat:<10}]  {item['check']}\n",tag)

        db.configure(state="disabled")
        self.status_var.set(f"Analysis complete. Score: {score}/100  |  Verdict: {risk['verdict']}")


if __name__ == "__main__":
    App().mainloop()
