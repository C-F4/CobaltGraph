#!/usr/bin/env python3
"""
Port Service Name Resolution
Maps port numbers to service names based on IANA assignments and common usage

Features:
- Well-known port (0-1023) mapping
- Registered port (1024-49151) mapping
- Ephemeral port detection (49152-65535)
- Flexible formatting options
"""

from typing import Optional, Tuple


class PortServiceResolver:
    """
    Resolve port numbers to service names

    Based on IANA Service Name and Transport Protocol Port Number Registry
    with additions for common modern services.
    """

    # Well-known ports (0-1023) and common registered ports
    WELL_KNOWN_PORTS = {
        # Remote Access & Management
        20: ("FTP-DATA", "FTP Data Transfer"),
        21: ("FTP", "File Transfer Protocol"),
        22: ("SSH", "Secure Shell"),
        23: ("TELNET", "Telnet"),
        25: ("SMTP", "Simple Mail Transfer"),
        53: ("DNS", "Domain Name System"),
        67: ("DHCP-S", "DHCP Server"),
        68: ("DHCP-C", "DHCP Client"),
        69: ("TFTP", "Trivial File Transfer"),
        80: ("HTTP", "Hypertext Transfer"),
        110: ("POP3", "Post Office Protocol v3"),
        119: ("NNTP", "Network News Transfer"),
        123: ("NTP", "Network Time Protocol"),
        137: ("NBNS", "NetBIOS Name Service"),
        138: ("NBDG", "NetBIOS Datagram"),
        139: ("NBSS", "NetBIOS Session"),
        143: ("IMAP", "Internet Message Access"),
        161: ("SNMP", "SNMP Agent"),
        162: ("SNMPTRAP", "SNMP Trap"),
        179: ("BGP", "Border Gateway Protocol"),
        194: ("IRC", "Internet Relay Chat"),
        389: ("LDAP", "Lightweight Directory Access"),
        443: ("HTTPS", "HTTP Secure"),
        445: ("SMB", "Server Message Block"),
        465: ("SMTPS", "SMTP over SSL"),
        500: ("ISAKMP", "IPSec Key Exchange"),
        514: ("SYSLOG", "Syslog"),
        515: ("LPD", "Line Printer Daemon"),
        520: ("RIP", "Routing Information Protocol"),
        546: ("DHCPv6-C", "DHCPv6 Client"),
        547: ("DHCPv6-S", "DHCPv6 Server"),
        554: ("RTSP", "Real Time Streaming"),
        587: ("SUBMISSION", "Mail Submission"),
        636: ("LDAPS", "LDAP over SSL"),
        853: ("DNS-TLS", "DNS over TLS"),
        873: ("RSYNC", "Rsync"),
        993: ("IMAPS", "IMAP over SSL"),
        995: ("POP3S", "POP3 over SSL"),

        # Database Ports
        1433: ("MSSQL", "Microsoft SQL Server"),
        1434: ("MSSQL-M", "MSSQL Monitor"),
        1521: ("ORACLE", "Oracle Database"),
        3306: ("MYSQL", "MySQL Database"),
        5432: ("PGSQL", "PostgreSQL"),
        6379: ("REDIS", "Redis"),
        27017: ("MONGODB", "MongoDB"),
        9042: ("CASSANDRA", "Cassandra CQL"),
        5984: ("COUCHDB", "CouchDB"),
        8529: ("ARANGODB", "ArangoDB"),

        # Messaging & Queues
        5672: ("AMQP", "Advanced Message Queue"),
        5671: ("AMQPS", "AMQP over SSL"),
        1883: ("MQTT", "MQTT"),
        8883: ("MQTTS", "MQTT over SSL"),
        9092: ("KAFKA", "Apache Kafka"),
        4222: ("NATS", "NATS"),

        # Remote Desktop & VNC
        3389: ("RDP", "Remote Desktop Protocol"),
        5900: ("VNC", "Virtual Network Computing"),
        5901: ("VNC-1", "VNC Display 1"),
        5902: ("VNC-2", "VNC Display 2"),
        6000: ("X11", "X Window System"),

        # Web Services & APIs
        8080: ("HTTP-ALT", "HTTP Alternate"),
        8443: ("HTTPS-ALT", "HTTPS Alternate"),
        8000: ("HTTP-ALT2", "HTTP Alternate 2"),
        8888: ("HTTP-PROXY", "HTTP Proxy"),
        9000: ("HTTP-ALT3", "HTTP Alternate 3"),
        9443: ("HTTPS-ALT2", "HTTPS Alternate 2"),
        3000: ("DEV-HTTP", "Development HTTP"),
        4000: ("DEV-HTTP2", "Development HTTP 2"),
        5000: ("DEV-HTTP3", "Development HTTP 3"),
        4443: ("PHAROS", "HTTPS Alt (Pharos)"),

        # Container & Orchestration
        2375: ("DOCKER", "Docker API"),
        2376: ("DOCKERS", "Docker API TLS"),
        2377: ("SWARM", "Docker Swarm"),
        6443: ("K8S-API", "Kubernetes API"),
        10250: ("KUBELET", "Kubelet API"),
        10255: ("KUBELET-RO", "Kubelet Read-Only"),
        2379: ("ETCD-C", "etcd Client"),
        2380: ("ETCD-P", "etcd Peer"),

        # Monitoring & Observability
        9090: ("PROMETHEUS", "Prometheus"),
        9091: ("PUSHGATEWAY", "Prometheus Pushgateway"),
        3100: ("LOKI", "Grafana Loki"),
        4317: ("OTLP", "OpenTelemetry"),
        4318: ("OTLP-HTTP", "OpenTelemetry HTTP"),
        9411: ("ZIPKIN", "Zipkin"),
        14268: ("JAEGER", "Jaeger Collector"),
        8125: ("STATSD", "StatsD"),

        # Search & Analytics
        9200: ("ELASTIC", "Elasticsearch"),
        9300: ("ELASTIC-T", "Elasticsearch Transport"),
        5601: ("KIBANA", "Kibana"),
        8983: ("SOLR", "Apache Solr"),
        9997: ("SPLUNK", "Splunk Forwarder"),
        8089: ("SPLUNK-M", "Splunk Management"),

        # Proxy & Load Balancing
        8001: ("KONG-A", "Kong Admin"),
        1080: ("SOCKS", "SOCKS Proxy"),
        3128: ("SQUID", "Squid Proxy"),
        8118: ("PRIVOXY", "Privoxy"),
        9080: ("GLASSFISH", "GlassFish HTTP"),

        # Mail
        24: ("PRIV-MAIL", "Private Mail System"),
        109: ("POP2", "Post Office Protocol v2"),
        220: ("IMAP3", "IMAP v3"),
        585: ("IMAP4-SSL", "IMAP4 over SSL"),

        # File Sharing
        111: ("RPC", "RPC Portmapper"),
        2049: ("NFS", "Network File System"),
        548: ("AFP", "Apple Filing Protocol"),
        631: ("IPP", "Internet Printing"),

        # VPN & Tunneling
        1194: ("OPENVPN", "OpenVPN"),
        1701: ("L2TP", "Layer 2 Tunneling"),
        1723: ("PPTP", "Point-to-Point Tunneling"),
        4500: ("NAT-T", "IPSec NAT Traversal"),
        51820: ("WIREGUARD", "WireGuard VPN"),

        # Gaming & Streaming
        25565: ("MINECRAFT", "Minecraft"),
        27015: ("SRCDS", "Source Engine"),
        19132: ("MCPE", "Minecraft Bedrock"),

        # Misc
        88: ("KERBEROS", "Kerberos"),
        135: ("MSRPC", "Microsoft RPC"),
        464: ("KPASSWD", "Kerberos Password"),
        749: ("KADMIN", "Kerberos Admin"),
        1812: ("RADIUS", "RADIUS Authentication"),
        1813: ("RADIUS-A", "RADIUS Accounting"),
        2082: ("CPANEL", "cPanel"),
        2083: ("CPANELS", "cPanel SSL"),
        8081: ("BLACKICE", "BlackIce / HTTP Alt"),
        10000: ("WEBMIN", "Webmin"),
        32400: ("PLEX", "Plex Media Server"),
        8096: ("EMBY", "Emby Media Server"),
        8123: ("HOMEASSIST", "Home Assistant"),
        1900: ("SSDP", "SSDP/UPnP"),
        5353: ("MDNS", "Multicast DNS"),
        11211: ("MEMCACHED", "Memcached"),
    }

    # Ephemeral port range (IANA recommendation)
    EPHEMERAL_START = 49152
    EPHEMERAL_END = 65535

    # Dynamic/private port range (broader definition)
    DYNAMIC_START = 32768

    @classmethod
    def resolve(cls, port: int) -> Optional[Tuple[str, str]]:
        """
        Resolve port number to service name and description

        Args:
            port: Port number (0-65535)

        Returns:
            Tuple of (short_name, description) or None if unknown
        """
        if port in cls.WELL_KNOWN_PORTS:
            return cls.WELL_KNOWN_PORTS[port]
        return None

    @classmethod
    def get_service_name(cls, port: int) -> str:
        """
        Get short service name for port

        Args:
            port: Port number

        Returns:
            Service name or port number as string
        """
        info = cls.resolve(port)
        if info:
            return info[0]
        return str(port)

    @classmethod
    def format_port(cls, port: int, style: str = "short") -> str:
        """
        Format port with service name

        Args:
            port: Port number
            style: Format style
                - "short": "443/HTTPS"
                - "long": "443 (HTTPS)"
                - "name_only": "HTTPS" (or port number if unknown)
                - "number_only": "443"

        Returns:
            Formatted port string
        """
        if style == "number_only":
            return str(port)

        info = cls.resolve(port)
        if info:
            name = info[0]
            if style == "short":
                return f"{port}/{name}"
            elif style == "long":
                return f"{port} ({name})"
            elif style == "name_only":
                return name
        else:
            if style == "name_only":
                return str(port)
            return str(port)

        return str(port)

    @classmethod
    def is_ephemeral(cls, port: int) -> bool:
        """
        Check if port is in ephemeral range (49152-65535)

        Ephemeral ports are dynamically assigned by the OS for outbound connections.
        They're normal as source ports but unusual as destination ports.

        Args:
            port: Port number

        Returns:
            True if port is ephemeral
        """
        return cls.EPHEMERAL_START <= port <= cls.EPHEMERAL_END

    @classmethod
    def is_dynamic(cls, port: int) -> bool:
        """
        Check if port is in dynamic/private range (32768-65535)

        This is a broader definition used by some systems.

        Args:
            port: Port number

        Returns:
            True if port is in dynamic range
        """
        return cls.DYNAMIC_START <= port <= cls.EPHEMERAL_END

    @classmethod
    def is_well_known(cls, port: int) -> bool:
        """
        Check if port is in well-known range (0-1023)

        Args:
            port: Port number

        Returns:
            True if port is well-known
        """
        return 0 <= port <= 1023

    @classmethod
    def is_registered(cls, port: int) -> bool:
        """
        Check if port is in registered range (1024-49151)

        Args:
            port: Port number

        Returns:
            True if port is registered
        """
        return 1024 <= port < cls.EPHEMERAL_START

    @classmethod
    def get_port_category(cls, port: int) -> str:
        """
        Get the category of a port

        Args:
            port: Port number

        Returns:
            Category name: "well_known", "registered", or "dynamic"
        """
        if cls.is_well_known(port):
            return "well_known"
        elif cls.is_registered(port):
            return "registered"
        else:
            return "dynamic"

    @classmethod
    def is_high_risk(cls, port: int) -> bool:
        """
        Check if port is commonly associated with high-risk services

        Args:
            port: Port number

        Returns:
            True if port is high-risk
        """
        high_risk_ports = {
            22,     # SSH (brute force target)
            23,     # Telnet (unencrypted)
            25,     # SMTP (spam relay)
            135,    # MSRPC
            137,    # NetBIOS NS
            138,    # NetBIOS DG
            139,    # NetBIOS SS
            445,    # SMB
            1433,   # MSSQL
            1434,   # MSSQL Browser
            3306,   # MySQL
            3389,   # RDP
            5432,   # PostgreSQL
            5900,   # VNC
            6379,   # Redis
            27017,  # MongoDB
        }
        return port in high_risk_ports

    @classmethod
    def get_service_info(cls, port: int) -> dict:
        """
        Get comprehensive information about a port

        Args:
            port: Port number

        Returns:
            Dictionary with port information
        """
        info = cls.resolve(port)
        return {
            "port": port,
            "service_name": info[0] if info else None,
            "description": info[1] if info else None,
            "category": cls.get_port_category(port),
            "is_well_known": cls.is_well_known(port),
            "is_registered": cls.is_registered(port),
            "is_ephemeral": cls.is_ephemeral(port),
            "is_dynamic": cls.is_dynamic(port),
            "is_high_risk": cls.is_high_risk(port),
            "formatted_short": cls.format_port(port, "short"),
            "formatted_long": cls.format_port(port, "long"),
        }


# Convenience functions
def format_port(port: int, style: str = "short") -> str:
    """Format port with service name"""
    return PortServiceResolver.format_port(port, style)


def get_service_name(port: int) -> str:
    """Get service name for port"""
    return PortServiceResolver.get_service_name(port)


def is_ephemeral_port(port: int) -> bool:
    """Check if port is ephemeral"""
    return PortServiceResolver.is_ephemeral(port)


if __name__ == "__main__":
    # Test the service
    print("Port Service Name Resolution Test")
    print("=" * 50)

    test_ports = [22, 80, 443, 3389, 8080, 3306, 5432, 27017, 50000, 65000]

    for port in test_ports:
        info = PortServiceResolver.get_service_info(port)
        print(f"\nPort {port}:")
        print(f"  Short: {info['formatted_short']}")
        print(f"  Long:  {info['formatted_long']}")
        print(f"  Category: {info['category']}")
        print(f"  High Risk: {info['is_high_risk']}")
        print(f"  Ephemeral: {info['is_ephemeral']}")
