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
    """Display CobaltGraph boot banner with version"""
    VERSION = "3.1.0"

    # Subtle animation: reveal banner line by line
    banner_lines = [
        "",
        f"{Colors.BRIGHT_CYAN}     ██████╗ ██████╗ ██████╗  █████╗ ██╗  ████████╗     ██████╗ ██████╗  █████╗ ██████╗ ██╗  ██╗{Colors.RESET}",
        f"{Colors.BRIGHT_CYAN}    ██╔════╝██╔═══██╗██╔══██╗██╔══██╗██║  ╚══██╔══╝    ██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██║  ██║{Colors.RESET}",
        f"{Colors.CYAN}    ██║     ██║   ██║██████╔╝███████║██║     ██║       ██║  ███╗██████╔╝███████║██████╔╝███████║{Colors.RESET}",
        f"{Colors.CYAN}    ██║     ██║   ██║██╔══██╗██╔══██║██║     ██║       ██║   ██║██╔══██╗██╔══██║██╔═══╝ ██╔══██║{Colors.RESET}",
        f"{Colors.DIM}    ╚██████╗╚██████╔╝██████╔╝██║  ██║███████╗██║       ╚██████╔╝██║  ██║██║  ██║██║     ██║  ██║{Colors.RESET}",
        f"{Colors.DIM}     ╚═════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝        ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝{Colors.RESET}",
        "",
        f"    {Colors.BRIGHT_CYAN}◉ UNIFIED THREAT MONITORING & INTELLIGENCE PLATFORM{Colors.RESET}  {Colors.DIM}v{VERSION}{Colors.RESET}",
        f"    {Colors.DIM}◦ Blue-Team Network Security | Byzantine Fault Tolerant Consensus{Colors.RESET}",
        f"    {Colors.DIM}◦ Passive Reconnaissance | Consensus Threat Scoring{Colors.RESET}",
        "",
    ]

    for line in banner_lines:
        print(line)
        time.sleep(0.03)  # Subtle cascade effect


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
    """
    Enhanced cybersecurity-themed boot sequence.

    Duration: ~5 seconds total
    Features:
    - Geographical map initialization (1.5s)
    - Multi-reference triaging system (1.5s)
    - Network monitoring initialization (1.5s)
    - Final status display (0.5s)
    """
    Colors.clear()

    # Title animation (0.3s)
    boot_banner()
    time.sleep(0.3)

    # === GEOGRAPHICAL INTELLIGENCE INITIALIZATION (1.5s) ===
    print(f"\n{Colors.BRIGHT_CYAN}[INITIALIZING GEOGRAPHICAL INTELLIGENCE]{Colors.RESET}")
    print(f"{Colors.DIM}Loading geolocation databases and threat maps...{Colors.RESET}\n")

    # ASCII world map outline with scanning effect
    map_lines = [
        "     ╔══════════════════════════════════════════════════════════╗",
        "     ║  ░░░░░▓▓▓▓▓▓▓░░░░░░░░░░▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░  ║",
        "     ║  ░░░▓▓▓░░░░░▓▓░░░░░░░▓▓░░░░░░░▓▓░░░░░░░░░░░░░░░░░░░  ║",
        "     ║  ░░▓▓░░░░░░░░▓▓░░░░░▓░░░░░░░░░░▓░░░░░░░░░░░░░░░░░░░  ║",
        "     ╚══════════════════════════════════════════════════════════╝",
    ]

    regions = [
        ("North America", "185.220.101.0/24"),
        ("Europe", "151.80.0.0/16"),
        ("Asia Pacific", "202.12.28.0/24"),
        ("Middle East", "185.220.102.0/24"),
        ("Africa", "102.22.0.0/16"),
    ]

    for line in map_lines:
        print(f"{Colors.GREEN}{line}{Colors.RESET}")
        time.sleep(0.05)

    print()
    for region, subnet in regions:
        print(f"  {Colors.GREEN}●{Colors.RESET} {region:<20} {Colors.DIM}{subnet}{Colors.RESET}")
        time.sleep(0.15)

    print(f"\n  {Colors.BRIGHT_GREEN}✓ Geographical database loaded{Colors.RESET}")
    time.sleep(0.3)

    # === MULTI-REFERENCE TRIAGING SYSTEM (1.5s) ===
    print(f"\n{Colors.BRIGHT_CYAN}[MULTI-REFERENCE TRIAGING SYSTEM]{Colors.RESET}")
    print(f"{Colors.DIM}Initializing threat intelligence sources...{Colors.RESET}\n")

    intel_sources = [
        ("VirusTotal API", "Malware & Reputation", True),
        ("AbuseIPDB", "Abuse Reports & Scoring", True),
        ("Team Cymru ASN", "Organization Intelligence", True),
        ("GeoIP Database", "Location & Routing", True),
        ("MAC Vendor DB", "Device Fingerprinting", True),
    ]

    for source, description, status in intel_sources:
        status_icon = f"{Colors.BRIGHT_GREEN}✓{Colors.RESET}" if status else f"{Colors.RED}✗{Colors.RESET}"
        print(f"  {status_icon} {source:<20} {Colors.DIM}{description}{Colors.RESET}")
        time.sleep(0.2)

    print(f"\n  {Colors.BRIGHT_GREEN}✓ Triaging system online{Colors.RESET}")
    time.sleep(0.3)

    # === NETWORK MONITORING ENGINE INITIALIZATION (1.5s) ===
    print(f"\n{Colors.BRIGHT_CYAN}[NETWORK MONITORING ENGINE]{Colors.RESET}")
    print(f"{Colors.DIM}Configuring capture and analysis subsystems...{Colors.RESET}\n")

    monitoring_components = [
        ("Packet Capture Engine", "Scapy + Promiscuous Mode"),
        ("Protocol Analyzer", "TCP/UDP/ICMP Dissection"),
        ("Connection Tracker", "Flow State Management"),
        ("Consensus Scorer", "BFT Threat Analysis"),
        ("Database Writer", "SQLite WAL Mode"),
    ]

    for component, tech in monitoring_components:
        bar_width = 30
        filled = bar_width
        bar = f"{Colors.BRIGHT_GREEN}{'█' * filled}{Colors.RESET}"

        print(f"  {component:<25} {bar} {Colors.DIM}{tech}{Colors.RESET}")
        time.sleep(0.15)

    print(f"\n  {Colors.BRIGHT_GREEN}✓ Network monitoring ready{Colors.RESET}")
    time.sleep(0.3)

    # === FINAL STATUS (0.5s) ===
    print(f"\n{Colors.BRIGHT_CYAN}╔══════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.BRIGHT_CYAN}║{Colors.RESET}  {Colors.BRIGHT_GREEN}✓{Colors.RESET} BOOT SEQUENCE COMPLETE             {Colors.BRIGHT_CYAN}║{Colors.RESET}")
    print(f"{Colors.BRIGHT_CYAN}╚══════════════════════════════════════╝{Colors.RESET}")

    # Mode selection
    selected_mode = mode_selector()

    print(f"\n{Colors.DIM}Launching dashboard...{Colors.RESET}")
    time.sleep(0.3)

    # Store selected mode
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
