# CobaltGraph - Start Here
## Choose Your Platform

---

## 🪟 Windows

### Method 1: Double-click (Easiest)
```
Double-click: cobaltgraph.bat
```

### Method 2: Command Prompt
```cmd
cobaltgraph.bat
```

### Method 3: PowerShell
```powershell
python cobaltgraph.py
```

### For Network-Wide Monitoring:
```powershell
# Run PowerShell as Administrator, then:
python cobaltgraph.py
```

---

## 🐧 WSL (Windows Subsystem for Linux)

### Device-Only Mode:
```bash
python3 cobaltgraph.py
# OR
bash bin/cobaltgraph
# OR
./bin/cobaltgraph
```

### Network-Wide Mode (Recommended):
```bash
sudo python3 cobaltgraph.py
# OR
sudo bash bin/cobaltgraph
# OR
sudo ./bin/cobaltgraph
```

---

## 🐧 Linux

### Device-Only Mode:
```bash
python3 cobaltgraph.py
# OR
./bin/cobaltgraph
```

### Network-Wide Mode (Recommended):
```bash
sudo python3 cobaltgraph.py
# OR
sudo ./bin/cobaltgraph
```

---

## 🍎 macOS

### Device-Only Mode:
```bash
python3 cobaltgraph.py
# OR
./bin/cobaltgraph
```

### Network-Wide Mode (Requires root):
```bash
sudo python3 cobaltgraph.py
# OR
sudo ./bin/cobaltgraph
```

---

## ❓ Which Method Should I Use?

| Platform | Easiest Method | Network-Wide Method |
|----------|---------------|---------------------|
| **Windows** | `cobaltgraph.bat` | Admin PowerShell: `python cobaltgraph.py` |
| **WSL** | `python3 cobaltgraph.py` | `sudo python3 cobaltgraph.py` |
| **Linux** | `python3 cobaltgraph.py` | `sudo python3 cobaltgraph.py` |
| **macOS** | `python3 cobaltgraph.py` | `sudo python3 cobaltgraph.py` |

---

## 🔍 Health Check

### Windows:
```cmd
python cobaltgraph.py --health
```

### WSL/Linux/macOS:
```bash
python3 cobaltgraph.py --health
# OR
./bin/cobaltgraph-health
```

---

## 🆘 Troubleshooting

### "python: command not found"
**Solution**: Install Python 3.8+ from https://www.python.org/downloads/

### "Permission denied" (Linux/WSL/macOS)
**Solution**: Add sudo:
```bash
sudo python3 cobaltgraph.py
```

### "Port 8080 already in use"
**Solution**: Kill existing CobaltGraph instance:
```bash
# Windows:
taskkill /F /IM python.exe

# WSL/Linux/macOS:
pkill -f cobaltgraph
```

### "No module named 'requests'"
**Solution**: Install dependencies:
```bash
pip install -r requirements.txt
```

---

## 📖 Next Steps

After starting CobaltGraph:
1. Read and accept the legal disclaimer
2. Choose your monitoring mode (network or device)
3. Select interface type (web dashboard or terminal)
4. Access dashboard at: **http://localhost:8080**

---

## 📚 More Information

- **Full Documentation**: See `README.md`
- **Quick Start Guide**: See `QUICKSTART.txt`
- **Demo Guide**: See `SHOWCASE.md`
- **Configuration**: See `config/README.md`

---

**The easiest way to start on ANY platform:**
```bash
python cobaltgraph.py
# OR (Windows only)
cobaltgraph.bat
```

That's it! 🚀
