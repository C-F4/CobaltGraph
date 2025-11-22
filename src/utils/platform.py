"""
CobaltGraph Platform Detection Utilities
OS and capability detection

Detects:
- Operating system (Linux, Windows, macOS, WSL)
- Network capture capabilities (raw sockets, promiscuous mode)
- Terminal capabilities (TTY, ncurses support)
- Permissions (root/admin)
"""

import os
import sys
import platform
import subprocess
from typing import Dict

def get_platform_info() -> Dict[str, any]:
    """
    Get comprehensive platform information

    Returns:
        Dict with platform details
    """
    return {
        'os': get_os_type(),
        'is_wsl': is_wsl(),
        'is_root': is_root(),
        'has_raw_sockets': can_create_raw_socket(),
        'has_tty': has_terminal(),
        'python_version': sys.version,
        'platform': platform.platform(),
    }


def get_os_type() -> str:
    """
    Detect operating system

    Returns:
        'linux', 'windows', 'darwin' (macOS), or 'unknown'
    """
    return sys.platform


def is_wsl() -> bool:
    """
    Detect if running in Windows Subsystem for Linux

    Returns:
        True if WSL, False otherwise
    """
    try:
        with open('/proc/version', 'r') as f:
            return 'microsoft' in f.read().lower()
    except:
        return False


def is_root() -> bool:
    """
    Check if running with root/admin privileges

    Returns:
        True if root/admin, False otherwise
    """
    if get_os_type() == 'win32':
        # Windows admin check
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        # Unix root check
        return os.geteuid() == 0


def can_create_raw_socket() -> bool:
    """
    Test if we can create raw sockets for packet capture

    Returns:
        True if raw sockets available, False otherwise
    """
    try:
        import socket
        # Try to create AF_PACKET raw socket (Linux)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.close()
        return True
    except (OSError, AttributeError):
        return False


def has_terminal() -> bool:
    """
    Check if running in an interactive terminal

    Returns:
        True if TTY available, False otherwise
    """
    return sys.stdin.isatty() and sys.stdout.isatty()


def get_terminal_type() -> str:
    """
    Get terminal type from TERM environment variable

    Returns:
        Terminal type string (e.g., 'xterm-256color')
    """
    return os.environ.get('TERM', 'dumb')


def supports_ncurses() -> bool:
    """
    Check if terminal supports ncurses

    Returns:
        True if ncurses likely supported, False otherwise
    """
    if not has_terminal():
        return False

    term = get_terminal_type()
    if term in ('dumb', ''):
        return False

    # Try to import curses
    try:
        import curses
        return True
    except ImportError:
        return False


def get_network_interfaces() -> list:
    """
    Get list of network interfaces

    Returns:
        List of interface names
    """
    # TODO: Implement cross-platform interface detection
    # Use netifaces or parse system commands
    return []


def print_platform_info():
    """Print platform information (for debugging)"""
    info = get_platform_info()
    print("Platform Information:")
    print(f"  OS: {info['os']}")
    print(f"  WSL: {info['is_wsl']}")
    print(f"  Root/Admin: {info['is_root']}")
    print(f"  Raw Sockets: {info['has_raw_sockets']}")
    print(f"  TTY: {info['has_tty']}")
    print(f"  Terminal: {get_terminal_type()}")
    print(f"  Ncurses: {supports_ncurses()}")
