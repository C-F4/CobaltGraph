#!/usr/bin/env python3
"""
Analyze VPN patterns in CobaltGraph data
"""
import sqlite3
import sys
from collections import Counter

def analyze_vpn_patterns(db_path):
    """Analyze connection patterns to identify VPN behavior"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("=" * 70)
    print("VPN Connection Analysis")
    print("=" * 70)
    print()
    
    # Total connections
    cursor.execute("SELECT COUNT(*) FROM connections")
    total = cursor.fetchone()[0]
    
    # VPN DNS connections (src=dst, port 53)
    cursor.execute("""
        SELECT COUNT(*) FROM connections 
        WHERE src_ip = dst_ip 
        AND dst_port = 53
        AND (dst_ip LIKE '10.%' OR dst_ip LIKE '172.%' OR dst_ip LIKE '192.168.%')
    """)
    vpn_dns = cursor.fetchone()[0]
    
    # Real external connections
    cursor.execute("""
        SELECT COUNT(*) FROM connections 
        WHERE dst_country IS NOT NULL
    """)
    external = cursor.fetchone()[0]
    
    # Local network (non-VPN DNS)
    local = total - vpn_dns - external
    
    print(f"📊 Connection Breakdown:")
    print(f"   Total Connections: {total}")
    print(f"   VPN DNS Protection: {vpn_dns} ({vpn_dns/total*100:.1f}%)")
    print(f"   Real External: {external} ({external/total*100:.1f}%)")
    print(f"   Other Local: {local} ({local/total*100:.1f}%)")
    print()
    
    # VPN DNS details
    if vpn_dns > 0:
        print("🔒 VPN DNS Protection Details:")
        cursor.execute("""
            SELECT dst_ip, COUNT(*) as count 
            FROM connections 
            WHERE src_ip = dst_ip AND dst_port = 53
            GROUP BY dst_ip
        """)
        for row in cursor.fetchall():
            print(f"   {row[0]} → {row[1]} DNS queries")
        print()
    
    # External destinations
    print("🌍 Real External Destinations:")
    cursor.execute("""
        SELECT dst_org, dst_country, COUNT(*) as count
        FROM connections
        WHERE dst_country IS NOT NULL
        GROUP BY dst_org, dst_country
        ORDER BY count DESC
        LIMIT 10
    """)
    for row in cursor.fetchall():
        org = row[0] or "Unknown"
        country = row[1] or "Unknown"
        count = row[2]
        print(f"   {org:30s} ({country}) - {count} connections")
    
    conn.close()

if __name__ == '__main__':
    db_path = sys.argv[1] if len(sys.argv) > 1 else 'data/device.db'
    analyze_vpn_patterns(db_path)
