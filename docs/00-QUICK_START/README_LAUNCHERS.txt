CobaltGraph LAUNCHERS - QUICK REFERENCE
═══════════════════════════════════════════════════════════════════════════════

ALL LAUNCHERS ARE IN bin/ DIRECTORY:

  bin/cobaltgraph         → Bash script (Linux/WSL/macOS)
  bin/cobaltgraph.py      → Python launcher (ALL PLATFORMS) ⭐ RECOMMENDED
  bin/cobaltgraph.bat     → Batch file (Windows)
  bin/cobaltgraph-health  → Health check (Linux/WSL/macOS)

Symlinks in root for convenience:
  cobaltgraph.py  → bin/cobaltgraph.py
  cobaltgraph.bat → bin/cobaltgraph.bat

═══════════════════════════════════════════════════════════════════════════════

TO START CobaltGraph:

Universal (works everywhere):
  python cobaltgraph.py

Platform-specific:
  Windows:        cobaltgraph.bat  (double-click or run from CMD)
  Linux/WSL/Mac:  ./bin/cobaltgraph  (traditional Unix style)

═══════════════════════════════════════════════════════════════════════════════

WHY MULTIPLE LAUNCHERS?

Different platforms have different conventions:
  • Windows users expect .bat files
  • Unix users expect bash scripts in bin/
  • Python works everywhere

We provide all three so everyone can use their preferred method!

═══════════════════════════════════════════════════════════════════════════════

DOES BASH WORK ON WINDOWS?

NO - Bash does NOT work on native Windows (CMD/PowerShell).

YES - Bash DOES work in:
  ✅ WSL (Windows Subsystem for Linux)
  ✅ Git Bash
  ✅ Cygwin

That's why we provide cobaltgraph.bat for native Windows!

═══════════════════════════════════════════════════════════════════════════════

RECOMMENDED APPROACH:

Just remember ONE command that works everywhere:

  python cobaltgraph.py

Done! 🚀

═══════════════════════════════════════════════════════════════════════════════
