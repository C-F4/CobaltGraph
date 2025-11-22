"""
CobaltGraph Terminal UI Module
Experimental ncurses-based dashboard for SSH/headless environments

Platform Compatibility:
- ✅ Linux (native terminal)
- ✅ macOS (Terminal.app, iTerm2)
- ⚠️ WSL (Windows Terminal may work)
- ❌ Windows CMD/PowerShell (not supported)

Usage:
    from src.terminal.ultrathink import UltraThink
    ui = UltraThink()
    ui.start()
"""

from .ultrathink import UltraThink

__all__ = ['UltraThink']
