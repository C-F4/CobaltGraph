#!/usr/bin/env python3
"""
UltraThink - Real-time High-Value Intelligence Dashboard
Unified monitoring and analysis interface
"""

import asyncio
import curses
import json
import time
import threading
import queue
from datetime import datetime
from collections import deque, defaultdict
import subprocess
import socket
import struct

class UltraThink:
    def __init__(self):
        self.data_streams = {
            "network": deque(maxlen=100),
            "dns": deque(maxlen=50),
            "connections": deque(maxlen=200),
            "alerts": deque(maxlen=20),
            "metrics": defaultdict(int)
        }
        self.running = True
        self.update_queue = queue.Queue()
        self.high_value_targets = set()
        self.threat_score = 0
        
    def start(self):
        """Initialize all monitoring threads"""
        threads = [
            threading.Thread(target=self.network_monitor, daemon=True),
            threading.Thread(target=self.dns_monitor, daemon=True),
            threading.Thread(target=self.connection_tracker, daemon=True),
            threading.Thread(target=self.intelligence_processor, daemon=True)
        ]
        
        for t in threads:
            t.start()
            
        # Start UI
        curses.wrapper(self.render_ui)
        
    def network_monitor(self):
        """Real-time packet analysis"""
        while self.running:
            try:
                # WSL-compatible network monitoring
                result = subprocess.run(
                    ["ss", "-tunap"],
                    capture_output=True,
                    text=True
                )
                
                connections = []
                for line in result.stdout.split('\n')[1:]:
                    parts = line.split()
                    if len(parts) >= 5:
                        state = parts[1]
                        local = parts[3]
                        remote = parts[4]
                        
                        if state == "ESTAB":
                            connections.append({
                                "local": local,
                                "remote": remote,
                                "timestamp": time.time()
                            })
                            
                self.data_streams["connections"].extend(connections)
                self.data_streams["metrics"]["total_connections"] = len(connections)
                
                # Check for high-value connections
                for conn in connections:
                    remote_ip = conn["remote"].split(":")[0]
                    if self.is_high_value(remote_ip):
                        self.high_value_targets.add(remote_ip)
                        self.alert(f"High-value target: {remote_ip}")
                        
            except Exception as e:
                pass
                
            time.sleep(1)
            
    def dns_monitor(self):
        """Monitor DNS queries"""
        while self.running:
            try:
                # Parse system DNS cache
                result = subprocess.run(
                    ["powershell.exe", "Get-DnsClientCache | ConvertTo-Json"],
                    capture_output=True,
                    text=True
                )
                
                if result.stdout:
                    dns_entries = json.loads(result.stdout)
                    
                    for entry in dns_entries[:10]:  # Latest 10
                        self.data_streams["dns"].append({
                            "name": entry.get("Name", ""),
                            "data": entry.get("Data", ""),
                            "ttl": entry.get("TimeToLive", 0),
                            "timestamp": time.time()
                        })
                        
            except:
                pass
                
            time.sleep(5)
            
    def connection_tracker(self):
        """Track active connections and patterns"""
        while self.running:
            try:
                # Get current connections
                current_conns = len(self.data_streams["connections"])
                
                # Calculate metrics
                self.data_streams["metrics"]["connections_per_minute"] = current_conns
                
                # Pattern detection
                remote_ips = defaultdict(int)
                for conn in self.data_streams["connections"]:
                    ip = conn["remote"].split(":")[0]
                    remote_ips[ip] += 1
                    
                # Detect scanning behavior
                for ip, count in remote_ips.items():
                    if count > 10:
                        self.alert(f"Possible scan from {ip} ({count} connections)")
                        self.threat_score += 10
                        
            except:
                pass
                
            time.sleep(2)
            
    def intelligence_processor(self):
        """Process data streams for actionable intelligence"""
        while self.running:
            try:
                # Correlation engine
                dns_names = [d["name"] for d in self.data_streams["dns"]]
                
                # Check for suspicious patterns
                suspicious_domains = [
                    d for d in dns_names 
                    if any(bad in d.lower() for bad in ["tor", "vpn", "proxy"])
                ]
                
                if suspicious_domains:
                    self.alert(f"Suspicious DNS: {suspicious_domains[0]}")
                    self.threat_score += 5
                    
                # Update threat score decay
                self.threat_score = max(0, self.threat_score - 1)
                
            except:
                pass
                
            time.sleep(3)
            
    def is_high_value(self, ip):
        """Identify high-value targets"""
        # Private networks
        if ip.startswith(("10.", "172.", "192.168.")):
            return False
            
        # Known important ranges
        important_ranges = [
            "8.8.",      # Google DNS
            "1.1.",      # Cloudflare
            "208.67.",   # OpenDNS
        ]
        
        return any(ip.startswith(r) for r in important_ranges)
        
    def alert(self, message):
        """Add to alert stream"""
        alert = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "message": message,
            "level": "HIGH" if self.threat_score > 50 else "MEDIUM"
        }
        self.data_streams["alerts"].append(alert)
        
    def render_ui(self, stdscr):
        """Real-time UI rendering"""
        curses.curs_set(0)
        stdscr.nodelay(1)
        stdscr.timeout(100)
        
        # Color pairs
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)
        
        while self.running:
            try:
                stdscr.clear()
                height, width = stdscr.getmaxyx()
                
                # Header
                header = "═══ ULTRATHINK REAL-TIME INTELLIGENCE ═══"
                stdscr.addstr(0, (width - len(header)) // 2, header, 
                            curses.color_pair(4) | curses.A_BOLD)
                
                # Threat Score
                threat_color = 2 if self.threat_score > 50 else 3 if self.threat_score > 20 else 1
                stdscr.addstr(2, 2, f"THREAT LEVEL: {self.threat_score:3d}", 
                            curses.color_pair(threat_color) | curses.A_BOLD)
                
                # Metrics
                metrics = self.data_streams["metrics"]
                stdscr.addstr(2, 25, f"Connections: {metrics['total_connections']:3d}")
                stdscr.addstr(2, 45, f"High-Value Targets: {len(self.high_value_targets):2d}")
                
                # Active Connections
                stdscr.addstr(4, 2, "━━━ ACTIVE CONNECTIONS ━━━", curses.A_BOLD)
                y = 5
                for conn in list(self.data_streams["connections"])[-10:]:
                    if y >= height - 15:
                        break
                    remote = conn["remote"]
                    stdscr.addstr(y, 2, f"→ {remote[:50]}")
                    y += 1
                    
                # DNS Activity
                stdscr.addstr(4, width//2, "━━━ DNS QUERIES ━━━", curses.A_BOLD)
                y = 5
                for dns in list(self.data_streams["dns"])[-8:]:
                    if y >= height - 15:
                        break
                    name = dns["name"][:30]
                    stdscr.addstr(y, width//2, f"• {name}")
                    y += 1
                    
                # Alerts
                alert_y = height - 12
                stdscr.addstr(alert_y, 2, "━━━ ALERTS ━━━", 
                            curses.color_pair(2) | curses.A_BOLD)
                
                for i, alert in enumerate(list(self.data_streams["alerts"])[-8:]):
                    if alert_y + i + 1 >= height - 2:
                        break
                    color = 2 if alert["level"] == "HIGH" else 3
                    msg = f"[{alert['timestamp']}] {alert['message'][:width-20]}"
                    stdscr.addstr(alert_y + i + 1, 2, msg, curses.color_pair(color))
                    
                # Status line
                status = f"[Q]uit | Uptime: {int(time.time()) % 3600}s | Press any key to refresh"
                stdscr.addstr(height-1, 2, status, curses.A_DIM)
                
                stdscr.refresh()
                
                # Handle input
                key = stdscr.getch()
                if key == ord('q') or key == ord('Q'):
                    self.running = False
                    break
                    
            except curses.error:
                pass
                
            time.sleep(0.1)

def main():
    """Main entry point with comprehensive error handling"""
    import sys
    import os

    print("Initializing UltraThink...")
    print("Starting real-time monitoring dashboard...")

    # Pre-flight checks
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("\n❌ ERROR: Terminal UI requires an interactive terminal (TTY)")
        print("   This won't work when:")
        print("   • Running in a pipe or background process")
        print("   • Running in some IDE terminals")
        print("   • STDIN/STDOUT is redirected")
        print("\n💡 Solution: Use Web Dashboard instead")
        print("   Run: python cobaltgraph.py")
        print("   Select option: 1 (Web Dashboard)")
        sys.exit(1)

    # Check TERM environment variable
    term = os.environ.get('TERM', '')
    if not term or term == 'dumb':
        print(f"\n❌ ERROR: Invalid terminal type: '{term}'")
        print("   Terminal UI requires a proper terminal emulator")
        print("\n💡 Solution: Set TERM environment variable")
        print("   Example: export TERM=xterm-256color")
        print("   Or use: Web Dashboard (option 1)")
        sys.exit(1)

    print(f"✓ Terminal detected: {term}")
    time.sleep(1)

    ultra = UltraThink()

    try:
        ultra.start()
    except KeyboardInterrupt:
        pass
    except curses.error as e:
        print("\n")
        print("=" * 70)
        print("❌ TERMINAL UI ERROR: ncurses initialization failed")
        print("=" * 70)
        print(f"Error: {e}")
        print("")
        print("This usually happens when:")
        print("  • Terminal emulator doesn't support ncurses properly")
        print("  • Running in WSL with incompatible Windows terminal")
        print("  • Terminal size is too small")
        print("  • Terminal capabilities are limited")
        print("")
        print("Platform Compatibility:")
        print("  ✅ Linux (native terminal)     - Should work")
        print("  ✅ macOS (Terminal.app/iTerm)  - Should work")
        print("  ⚠️  WSL (Windows Terminal)      - May work")
        print("  ⚠️  WSL (other emulators)       - Often fails")
        print("  ❌ Windows (CMD/PowerShell)    - Not supported")
        print("")
        print("💡 RECOMMENDED SOLUTION: Use Web Dashboard")
        print("   The web dashboard works on ALL platforms and provides:")
        print("   • Better visualization (interactive maps)")
        print("   • Cross-platform compatibility")
        print("   • No terminal compatibility issues")
        print("")
        print("To use Web Dashboard:")
        print("   1. Run: python cobaltgraph.py")
        print("   2. Select option: 1 (Web Dashboard)")
        print("   3. Open browser: http://localhost:8080")
        print("=" * 70)
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        print("💡 Try Web Dashboard instead (option 1)")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        print("\nUltraThink shutdown complete.")

if __name__ == "__main__":
    main()