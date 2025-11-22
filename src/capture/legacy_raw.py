#!/usr/bin/env python3
"""
Grey Man - Passive Network Awareness Tool
Operates quietly without active scanning
"""

import socket
import struct
import threading
import time
import json
import sys
from datetime import datetime
from collections import defaultdict

class GreyMan:
    def __init__(self):
        self.running = False
        self.packet_buffer = []
        self.network_map = defaultdict(lambda: {"first_seen": None, "last_seen": None, "packets": 0})
        self.stealth_mode = True
        
    def passive_listen(self):
        """Listen to network traffic without sending any packets"""
        try:
            # Raw socket for packet sniffing (requires root)
            # 0x0003 captures all protocols
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
            while self.running:
                raw_data, addr = sock.recvfrom(65535)
                self.process_packet(raw_data)
                
        except PermissionError:
            # Log to stderr for subprocess to capture
            print("ERROR: Requires root. Run with sudo.", file=sys.stderr)
        except Exception as e:
            print(f"ERROR: Listener error: {e}", file=sys.stderr)
            
    def process_packet(self, data):
        """Extract basic info without deep inspection and output as JSON"""
        if len(data) < 14:
            return
            
        # Ethernet header
        eth_header = struct.unpack("!6s6sH", data[:14])
        eth_protocol = socket.ntohs(eth_header[2])
        
        # Only process IP packets (IPv4 and IPv6)
        if eth_protocol == 0x0800:  # IPv4
            ip_header = data[14:34]
            if len(ip_header) >= 20:
                src_ip = socket.inet_ntoa(ip_header[12:16])
                dst_ip = socket.inet_ntoa(ip_header[16:20])
                protocol_id = ip_header[9] # IP protocol (e.g., 6 for TCP, 17 for UDP)

                # Extract port numbers for TCP/UDP
                src_port = 0
                dst_port = 0
                if protocol_id == 6: # TCP
                    tcp_header = data[34:54]
                    if len(tcp_header) >= 20:
                        src_port = struct.unpack("!H", tcp_header[0:2])[0]
                        dst_port = struct.unpack("!H", tcp_header[2:4])[0]
                elif protocol_id == 17: # UDP
                    udp_header = data[34:42]
                    if len(udp_header) >= 8:
                        src_port = struct.unpack("!H", udp_header[0:2])[0]
                        dst_port = struct.unpack("!H", udp_header[2:4])[0]

                # Update network map silently
                self.update_map(src_ip)
                self.update_map(dst_ip)

                # Output as JSON for cobaltgraph_modular.py
                packet_info = {
                    "type": "connection", 
                    "timestamp": datetime.now().isoformat(),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol_id": protocol_id,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "packet_size": len(data)
                }
                print(json.dumps(packet_info), flush=True) # Flush to ensure immediate output

        elif eth_protocol == 0x86DD: # IPv6
            # IPv6 header is 40 bytes, starts after Ethernet header (14 bytes)
            ipv6_header = data[14:54]
            if len(ipv6_header) >= 40:
                # Source IP (bytes 8-23 relative to IPv6 header start)
                src_ip = socket.inet_ntop(socket.AF_INET6, ipv6_header[8:24])
                # Destination IP (bytes 24-39 relative to IPv6 header start)
                dst_ip = socket.inet_ntop(socket.AF_INET6, ipv6_header[24:40])
                
                # Next Header field (equivalent to protocol_id in IPv4) is at byte 6 of IPv6 header
                protocol_id = ipv6_header[6]
                
                src_port = 0
                dst_port = 0
                # TCP/UDP headers follow IPv6 header (54 bytes from start of packet)
                if protocol_id == 6: # TCP
                    tcp_header = data[54:74]
                    if len(tcp_header) >= 20:
                        src_port = struct.unpack("!H", tcp_header[0:2])[0]
                        dst_port = struct.unpack("!H", tcp_header[2:4])[0]
                elif protocol_id == 17: # UDP
                    udp_header = data[54:62]
                    if len(udp_header) >= 8:
                        src_port = struct.unpack("!H", udp_header[0:2])[0]
                        dst_port = struct.unpack("!H", udp_header[2:4])[0]

                self.update_map(src_ip)
                self.update_map(dst_ip)

                packet_info = {
                    "type": "connection", 
                    "timestamp": datetime.now().isoformat(),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol_id": protocol_id,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "packet_size": len(data)
                }
                print(json.dumps(packet_info), flush=True)

    def update_map(self, ip):
        """Track IPs without active probing"""
        now = datetime.now().isoformat()
        
        if not self.network_map[ip]["first_seen"]:
            self.network_map[ip]["first_seen"] = now
        
        self.network_map[ip]["last_seen"] = now
        self.network_map[ip]["packets"] += 1
        
    def get_network_summary(self):
        """Return passive observations"""
        active_hosts = []
        for ip, data in self.network_map.items():
            if data["packets"] > 10:  # Filter noise
                active_hosts.append({
                    "ip": ip,
                    "activity": data["packets"],
                    "duration": data["first_seen"]
                })
        return active_hosts
        
    def start(self):
        self.running = True
        listener = threading.Thread(target=self.passive_listen, daemon=True)
        listener.start()
        
    def stop(self):
        self.running = False
        
if __name__ == "__main__":
    """
    Main entry point for Grey Man network capture
    Outputs JSON-formatted connection events to stdout
    Compatible with CobaltGraph pipeline
    """
    print("Grey Man - Raw Packet Capture (requires sudo)", file=sys.stderr)
    print("Capturing network traffic...", file=sys.stderr)

    grey = GreyMan()
    grey.start()

    try:
        # Keep main thread alive
        while True:
            time.sleep(1)

            # Send heartbeat every 10 seconds
            if int(time.time()) % 10 == 0:
                active_hosts = len(grey.network_map)
                heartbeat = {
                    "type": "heartbeat",
                    "active_hosts": active_hosts
                }
                print(json.dumps(heartbeat), flush=True)
                print(f"💓 Heartbeat: {active_hosts} hosts tracked", file=sys.stderr)
                time.sleep(1)  # Avoid duplicate heartbeats

    except KeyboardInterrupt:
        print("\nStopping Grey Man...", file=sys.stderr)
        grey.stop()
        sys.exit(0)
