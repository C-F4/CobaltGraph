# CobaltGraph on Windows - Installation Guide

## Quick Setup (5 Minutes)

### Step 1: Install Python
1. Download Python 3.8+ from: https://www.python.org/downloads/
2. **IMPORTANT**: Check "Add Python to PATH" during installation
3. Click "Install Now"

### Step 2: Install Dependencies
Open Command Prompt or PowerShell:
```cmd
pip install requests
```

### Step 3: Launch CobaltGraph
Navigate to CobaltGraph folder and:

**Option A - Double-click:**
```
Double-click: cobaltgraph.bat
```

**Option B - Command line:**
```cmd
python cobaltgraph.py
```

### Step 4: For Network-Wide Monitoring (Optional)
1. Right-click PowerShell → "Run as Administrator"
2. Navigate to CobaltGraph folder
3. Run: `python cobaltgraph.py`

---

## Windows-Specific Notes

### Why Admin/sudo?
- **Device mode**: No admin needed - monitors your PC only
- **Network mode**: Admin needed - monitors entire network

### Firewall Prompt
Windows may ask about network access. Click "Allow" for:
- Python (python.exe)
- HTTP server (port 8080)

### Antivirus Warning
Some antivirus may flag raw socket usage as suspicious. This is normal for network monitoring tools. Add CobaltGraph folder to exclusions if needed.

### WSL vs Native Windows
CobaltGraph works on both:
- **Native Windows**: Use `cobaltgraph.bat` or `python cobaltgraph.py`
- **WSL**: Use `python3 cobaltgraph.py` inside WSL terminal

For best results on Windows, use WSL2 (Windows Subsystem for Linux).

---

## Verification

After installation, test:
```cmd
python cobaltgraph.py --help
```

Should show:
```
CobaltGraph Network Security Platform
...
```

---

## Troubleshooting

**"python is not recognized"**
→ Python not in PATH. Reinstall Python with "Add to PATH" checked.

**"pip is not recognized"**
→ Run: `python -m pip install requests`

**"Port 8080 in use"**
→ Another program using port 8080. Kill it or change CobaltGraph port in config.

**"Permission denied"**
→ Run PowerShell as Administrator

---

## Next Steps

After installation:
1. Run: `python cobaltgraph.py`
2. Accept legal disclaimer
3. Choose monitoring mode
4. Access dashboard: http://localhost:8080

See QUICKSTART.txt for full usage guide.
