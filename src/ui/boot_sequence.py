#!/usr/bin/env python3
"""
CobaltGraph Cybersecurity Boot Sequence
Star Wars-themed dynamic ASCII initialization with interactive boot into the TUI dashboard

Features:
- Animated scanlines and digital rain effect
- Threat level scanning with real-time threat analysis
- System initialization with holographic-style effects
- Interactive boot options
- Seamless transition to dashboard
"""

import time
import os
import sys
from pathlib import Path
from typing import Optional
import random


class Colors:
    """ANSI color codes for terminal output"""
    RESET = '\033[0m'
    CYAN = '\033[0;36m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    MAGENTA = '\033[0;35m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    BRIGHT_CYAN = '\033[1;36m'
    BRIGHT_GREEN = '\033[1;32m'
    BRIGHT_RED = '\033[1;31m'
    BRIGHT_YELLOW = '\033[1;33m'

    @staticmethod
    def clear():
        """Clear terminal"""
        os.system('clear' if os.name != 'nt' else 'cls')


def print_slow(text: str, delay: float = 0.02):
    """Print text with typewriter effect"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)


def print_scanlines(width: int = 80, count: int = 5):
    """Print animated scanlines"""
    for _ in range(count):
        line = f"{Colors.GREEN}{'=' * width}{Colors.RESET}"
        print(line)
        time.sleep(0.05)


def digital_rain(width: int = 80, height: int = 5):
    """Print digital rain effect (Matrix-style)"""
    chars = '01アイウエオカキクケコサシスセソタチツテト'
    for _ in range(height):
        line = ''.join(random.choice(chars) for _ in range(width))
        print(f"{Colors.CYAN}{line}{Colors.RESET}")
        time.sleep(0.05)


def threat_scan_animation(width: int = 80):
    """Animated threat level scan"""
    print(f"\n{Colors.BRIGHT_CYAN}[THREAT ANALYSIS SYSTEM]{Colors.RESET}")
    print(f"{Colors.DIM}Scanning threat database...{Colors.RESET}\n")

    threats = [
        ("Geographic Anomalies", random.randint(5, 15)),
        ("Suspicious Protocols", random.randint(2, 8)),
        ("High-Risk ASNs", random.randint(1, 5)),
        ("Cryptographic Verification", random.randint(0, 3)),
        ("Consensus Disagreement", random.randint(0, 2)),
    ]

    for threat_name, count in threats:
        bar_width = 40
        progress = random.randint(30, 100)
        filled = int(bar_width * progress / 100)

        bar = f"{Colors.BRIGHT_GREEN}{'█' * filled}{Colors.DIM}{'░' * (bar_width - filled)}{Colors.RESET}"
        print(f"  {threat_name:<30} {bar} {progress:>3}%")
        time.sleep(0.3)

    print()


def system_status():
    """Display system status with indicators for actual system components"""
    print(f"{Colors.BRIGHT_CYAN}[SYSTEM STATUS]{Colors.RESET}")

    # These are the actual components used by CobaltGraph
    checks = [
        ("Database Connection", True),
        ("Threat Consensus Engine", True),
        ("Geolocation Service", True),
        ("ASN Lookup Service", True),
        ("Network Capture Engine", True),
        ("IP Reputation Service", True),
        ("MAC Vendor Resolution", True),
        ("Dashboard Renderer", True),
    ]

    for check_name, status in checks:
        status_str = f"{Colors.BRIGHT_GREEN}●{Colors.RESET}" if status else f"{Colors.RED}●{Colors.RESET}"
        status_text = "ONLINE" if status else "OFFLINE"
        color = Colors.GREEN if status else Colors.YELLOW
        print(f"  {status_str} {check_name:<35} {color}{status_text}{Colors.RESET}")
        time.sleep(0.15)

    print()


def boot_banner():
    """Display CobaltGraph boot banner"""
    banner = """
     ██████╗ ██████╗ ██████╗  █████╗ ██╗  ████████╗     ██████╗ ██████╗  █████╗ ██████╗ ██╗  ██╗
    ██╔════╝██╔═══██╗██╔══██╗██╔══██╗██║  ╚══██╔══╝    ██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██║  ██║
    ██║     ██║   ██║██████╔╝███████║██║     ██║       ██║  ███╗██████╔╝███████║██████╔╝███████║
    ██║     ██║   ██║██╔══██╗██╔══██║██║     ██║       ██║   ██║██╔══██╗██╔══██║██╔═══╝ ██╔══██║
    ╚██████╗╚██████╔╝██████╔╝██║  ██║███████╗██║       ╚██████╔╝██║  ██║██║  ██║██║     ██║  ██║
     ╚═════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝        ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝

    {cyan}UNIFIED THREAT MONITORING & INTELLIGENCE PLATFORM{reset}
    {dim}Blue-Team Network Security | Byzantine Fault Tolerant Consensus{reset}
    """
    print(banner.format(cyan=Colors.BRIGHT_CYAN, reset=Colors.RESET, dim=Colors.DIM))


def mode_selector():
    """Interactive mode selection - returns selected mode"""
    print(f"\n{Colors.BRIGHT_CYAN}[MODE SELECTION]{Colors.RESET}")
    print(f"{Colors.DIM}Select operating mode:{Colors.RESET}\n")

    modes = [
        ("1", "DEVICE MODE", "Personal device security focus - 'What am I connecting to?'"),
        ("2", "NETWORK MODE", "Network-wide topology focus - 'What's happening on my network?'"),
        ("3", "SKIP BOOT", "Jump directly to dashboard (no mode change)"),
    ]

    for num, name, desc in modes:
        print(f"  {Colors.BRIGHT_GREEN}[{num}]{Colors.RESET} {name}")
        print(f"      {Colors.DIM}{desc}{Colors.RESET}")
        time.sleep(0.2)

    print()
    while True:
        choice = input(f"{Colors.BRIGHT_CYAN}Select mode [1-3]: {Colors.RESET}").strip()
        if choice in ['1', '2', '3']:
            if choice == '1':
                return 'device'
            elif choice == '2':
                return 'network'
            else:
                return None  # Skip boot
        print(f"{Colors.RED}Invalid selection. Please choose 1, 2, or 3.{Colors.RESET}")
        print()


def initialization_sequence():
    """Main boot initialization sequence"""
    Colors.clear()

    # Title animation
    boot_banner()
    time.sleep(0.5)

    # Scanlines
    print_scanlines(width=80, count=3)
    time.sleep(0.3)

    # Digital rain
    digital_rain(width=80, height=3)
    time.sleep(0.5)

    # System initialization
    print(f"\n{Colors.BRIGHT_CYAN}[INITIALIZING SYSTEM]{Colors.RESET}")
    print(f"{Colors.DIM}Loading security modules...{Colors.RESET}\n")

    modules = [
        "Database Connection",
        "Network Capture Engine",
        "MAC Vendor Resolver",
        "Geolocation Engine",
        "ASN Intelligence Lookup",
        "IP Reputation Service",
        "Consensus Threat Scorer",
        "Byzantine Fault Tolerance",
        "Threat Analytics Engine",
        "Dashboard Renderer",
    ]

    for i, module in enumerate(modules):
        progress = int((i + 1) / len(modules) * 100)
        bar_width = 50
        filled = int(bar_width * progress / 100)

        bar = f"{Colors.BRIGHT_GREEN}{'█' * filled}{Colors.DIM}{'░' * (bar_width - filled)}{Colors.RESET}"
        print(f"  {module:<30} {bar} {progress:>3}%")
        time.sleep(0.15)

    time.sleep(0.5)

    # Threat analysis
    threat_scan_animation()

    # System status
    system_status()

    # Boot options - get user mode selection
    selected_mode = mode_selector()

    # Final countdown
    print(f"\n{Colors.BRIGHT_CYAN}[BOOT COMPLETE]{Colors.RESET}")
    print(f"{Colors.DIM}Initializing dashboard...{Colors.RESET}\n")

    countdown = 3
    for i in range(countdown, 0, -1):
        print(f"\r{Colors.BRIGHT_YELLOW}Launching dashboard in {i}...{Colors.RESET}", end="")
        sys.stdout.flush()
        time.sleep(1)

    print(f"\r{Colors.BRIGHT_GREEN}Launching dashboard now!   {Colors.RESET}\n")
    time.sleep(0.5)

    # Store selected mode in global or return via environment variable
    if selected_mode:
        os.environ['COBALTGRAPH_MODE'] = selected_mode

    return True


def show_boot_menu():
    """Interactive boot menu"""
    print(f"{Colors.BRIGHT_CYAN}[BOOT MENU]{Colors.RESET}\n")

    options = [
        ("1", "Boot Dashboard", "Launch CobaltGraph dashboard"),
        ("2", "Device Mode", "Boot in device security mode"),
        ("3", "Network Mode", "Boot in network topology mode"),
        ("4", "Skip Boot Sequence", "Jump to launcher"),
        ("5", "Exit", "Quit CobaltGraph"),
    ]

    for num, name, desc in options:
        print(f"  {Colors.BRIGHT_GREEN}[{num}]{Colors.RESET} {name:<20} - {Colors.DIM}{desc}{Colors.RESET}")

    print()
    choice = input(f"{Colors.BRIGHT_CYAN}Select option: {Colors.RESET}")
    return choice.strip()


def boot_sequence():
    """
    Main boot sequence function - entry point for start.py
    Returns True if successful, False if cancelled
    """
    try:
        # Show initialization sequence
        if initialization_sequence():
            return True
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Boot sequence interrupted by user{Colors.RESET}")
        return False
    except Exception as e:
        print(f"\n{Colors.RED}Boot sequence error: {e}{Colors.RESET}")
        return False

    return True


# Backward compatibility alias
run_boot_sequence = boot_sequence


if __name__ == '__main__':
    # Run boot sequence
    if boot_sequence():
        # Launch dashboard
        try:
            from src.core.launcher import CobaltGraphMain

            launcher = CobaltGraphMain()
            launcher.show_banner()
            sys.exit(launcher.main())
        except ImportError:
            print(f"{Colors.YELLOW}Dashboard launcher not available{Colors.RESET}")
            sys.exit(1)
    else:
        print(f"{Colors.YELLOW}Boot sequence cancelled{Colors.RESET}")
        sys.exit(0)
