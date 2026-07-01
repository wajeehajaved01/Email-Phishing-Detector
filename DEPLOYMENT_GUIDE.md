# 📦 PyInstaller Deployment Guide
## Email Phishing Detection System — Standalone .exe Build

---

## ✅ Prerequisites

Make sure you're in your project folder and Python 3.10–3.12 is active:

```powershell
cd "D:\IS LAB\Email Phishing Detector 1"
python --version      # should be 3.10, 3.11, or 3.12
```

> ⚠️ PyInstaller does NOT fully support Python 3.14 yet.
> If you have 3.14, run all commands as: `py -3.12 -m pip ...`

---

## STEP 1 — Install dependencies

```powershell
pip install dnspython colorama requests pyinstaller
```

Verify PyInstaller installed:
```powershell
pyinstaller --version
```

---

## STEP 2 — Confirm your folder structure

Your project must look like this BEFORE building:

```
Email Phishing Detector 1\
├── gui.py                    ← entry point
├── main.py
├── phishing_detector.spec    ← build config
├── DEPLOYMENT_GUIDE.md
├── requirements.txt
├── analyzers\
│   ├── __init__.py           ← must exist (empty file)
│   ├── dns_checker.py
│   ├── email_parser.py
│   ├── header_analyzer.py
│   ├── keyword_analyzer.py
│   └── url_threat.py
├── scoring\
│   ├── __init__.py
│   └── risk_engine.py
├── report\
│   ├── __init__.py
│   └── report_generator.py
└── samples\
    ├── phishing_paypal.eml
    ├── suspicious_medium.eml
    └── legitimate_github.eml
```

If any `__init__.py` is missing:
```powershell
New-Item analyzers\__init__.py -ItemType File -Force
New-Item scoring\__init__.py   -ItemType File -Force
New-Item report\__init__.py    -ItemType File -Force
```

---

## STEP 3 — Test the app runs normally first

```powershell
python gui.py
```

The GUI must open and all 3 demo emails must work before you build.
**Never build a broken app — fix errors first.**

---

## STEP 4 — Build the executable

```powershell
pyinstaller phishing_detector.spec
```

Watch the terminal output. It will say:
```
Building EXE from EXE-00.toc
Appending PKG archive to EXE
Building EXE from EXE-00.toc completed successfully.
```

Build time: ~60–120 seconds on first run.

---

## STEP 5 — Find your executable

```
dist\
└── PhishingDetector.exe      ← your final executable
```

Double-click it — no Python installation needed on any Windows machine.

---

## STEP 6 — Test the .exe thoroughly

```powershell
.\dist\PhishingDetector.exe
```

Test all 3 demo buttons inside the app:
- 🔴 Demo: Phishing → should score 80–100, HIGH RISK
- 🟡 Demo: Suspicious → should score 35–65, MEDIUM RISK  
- 🟢 Demo: Legitimate → should score 0–30, LOW RISK

---

## TROUBLESHOOTING

### Problem: "ModuleNotFoundError: No module named 'dns'"
**Fix:** Add to hiddenimports in the .spec file:
```python
hiddenimports=['dns', 'dns.resolver', 'dns.rdatatype', 'dns.name']
```
Then rebuild.

### Problem: "Failed to execute script gui"
**Fix:** Temporarily change `console=False` to `console=True` in the spec,
rebuild, and run from terminal to see the actual error message.

### Problem: Sample .eml files not found inside .exe
**Fix:** The `datas` list in the spec handles this. Verify it includes:
```python
(os.path.join(ROOT, 'samples'), 'samples'),
```

### Problem: App opens but DNS checks show "Unknown"
**Fix:** This is normal — DNS queries use live internet.
If running offline, checks return "Unknown/Unverified" gracefully.

### Problem: exe is too large (>50MB)
**Fix:** UPX compression is already enabled in the spec (`upx=True`).
Install UPX separately: https://upx.github.io/
Place `upx.exe` in your PATH, then rebuild.

### Problem: Windows Defender flags the .exe
**Fix:** This is common with PyInstaller-built apps (false positive).
- Add an exclusion in Windows Security for your `dist\` folder
- For distribution: sign the exe with a code-signing certificate

---

## OPTIONAL: Add an application icon

1. Create or download a 256×256 `.ico` file, save as `assets\icon.ico`
2. Uncomment this line in `phishing_detector.spec`:
   ```python
   # icon='assets/icon.ico',
   ```
   Change to:
   ```python
   icon=os.path.join(ROOT, 'assets', 'icon.ico'),
   ```
3. Rebuild with `pyinstaller phishing_detector.spec`

---

## OPTIONAL: Reduce .exe size further

Add more excludes to the spec's `excludes` list:
```python
excludes=['matplotlib','numpy','pandas','PIL','cv2',
          'sklearn','torch','tensorflow','IPython',
          'xmlrpc','ftplib','imaplib','poplib',
          'sqlite3','doctest','pdb','profile','cProfile'],
```

---

## Quick Reference — All commands

```powershell
# First time setup
pip install dnspython colorama requests pyinstaller

# Test app
python gui.py

# Build exe
pyinstaller phishing_detector.spec

# Run built exe
.\dist\PhishingDetector.exe

# Rebuild after changes (clean build)
Remove-Item -Recurse -Force build, dist
pyinstaller phishing_detector.spec
```

---

## For your IS Lab submission

Include in your zip/folder:
```
submission\
├── PhishingDetector.exe       ← standalone executable
├── source_code\               ← all .py files
├── report\                    ← your written report (PDF)
└── screenshots\               ← GUI screenshots showing all 3 test cases
```
