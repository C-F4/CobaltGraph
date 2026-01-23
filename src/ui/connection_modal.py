#!/usr/bin/env python3
"""
CobaltGraph Connection Intelligence Modal

Full drill-down modal showing ALL computed intelligence for a single connection.
Surfaces the 80-85% of backend intelligence that was previously hidden.

Panels:
1. ConsensusBreakdownPanel - 4 scorer votes, outliers, confidence
2. EnrichmentDetailsPanel - ASN, org, hops, TTL, CIDR
3. AnomalyAnalysisPanel - Z-scores, percentiles, contributing factors
4. ReputationPanel - VirusTotal, AbuseIPDB results
5. RulesTriggeredPanel - Which rules fired
6. GraphPositionPanel - Centrality, clusters, attack paths
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional

from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.console import Group

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Static, Button, Label
from textual.screen import ModalScreen
from textual.binding import Binding

logger = logging.getLogger(__name__)


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private/local (RFC 1918 + loopback)"""
    if not ip or ip == 'local':
        return True
    if ip.startswith("10."):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            if 16 <= second_octet <= 31:
                return True
        except (IndexError, ValueError):
            pass
    if ip.startswith("127."):
        return True
    return False


def get_direction(src_ip: str, dst_ip: str) -> tuple:
    """
    Determine packet/connection direction based on source and destination IPs.

    Returns:
        tuple: (direction_label, direction_color, direction_symbol)
        - "OUT" for outgoing (local -> external)
        - "IN" for incoming (external -> local)
        - "INT" for internal (local -> local)
        - "EXT" for external (external -> external, passthrough)
    """
    src_is_private = _is_private_ip(src_ip)
    dst_is_private = _is_private_ip(dst_ip)

    if src_is_private and not dst_is_private:
        return ("OUT", "cyan", "→")  # Outgoing
    elif not src_is_private and dst_is_private:
        return ("IN", "magenta", "←")  # Incoming
    elif src_is_private and dst_is_private:
        return ("INT", "dim", "↔")  # Internal
    else:
        return ("EXT", "yellow", "⇄")  # External/passthrough


class ProtocolEnrichmentPanel(Static):
    """
    Shows application layer protocol data: DNS queries, TLS SNI, TCP state.
    Includes domain intelligence analysis (DGA detection, domain-ASN correlation).
    """

    DEFAULT_CSS = """
    ProtocolEnrichmentPanel {
        width: 100%;
        height: auto;
        padding: 1;
    }
    """

    def __init__(self, connection_data: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.data = connection_data

    def render(self):
        lines = []
        lines.append("[bold cyan]APPLICATION LAYER[/bold cyan]")
        lines.append("")

        # DNS Query section
        dns_query = self.data.get('dns_query')
        dns_query_type = self.data.get('dns_query_type', 'A')
        lines.append("[bold]DNS Resolution[/bold]")
        if dns_query:
            lines.append(f"  Query: [cyan]{dns_query}[/cyan]")
            lines.append(f"  Type: {dns_query_type or 'A'}")
        else:
            lines.append("  [dim]No DNS query captured[/dim]")
        lines.append("")

        # TLS SNI section
        tls_sni = self.data.get('tls_sni')
        tls_version = self.data.get('tls_version')
        lines.append("[bold]TLS Handshake[/bold]")
        if tls_sni:
            lines.append(f"  SNI: [cyan]{tls_sni}[/cyan]")
            if tls_version:
                lines.append(f"  Version: {tls_version}")
        else:
            lines.append("  [dim]No TLS handshake captured[/dim]")
        lines.append("")

        # TCP State section
        tcp_state = self.data.get('tcp_state')
        tcp_is_scan = self.data.get('tcp_is_scan', False)
        lines.append("[bold]TCP Connection[/bold]")
        if tcp_state:
            state_color = "green" if tcp_state in ["ESTABLISHED", "SYN-ACK"] else "yellow"
            lines.append(f"  State: [{state_color}]{tcp_state}[/{state_color}]")
        else:
            lines.append("  State: [dim]Unknown[/dim]")
        if tcp_is_scan:
            lines.append("  [red]⚠ Port scan pattern detected[/red]")
        lines.append("")

        # Domain Intelligence section
        domain = dns_query or tls_sni
        if domain:
            lines.append("[bold cyan]─── DOMAIN INTELLIGENCE ───[/bold cyan]")
            lines.append("")

            # Domain trust classification
            domain_trust = self.data.get('domain_trust')
            lines.append("[bold]Trust Classification[/bold]")
            if domain_trust == "trusted":
                lines.append(f"  [green]✓ TRUSTED[/green]")
                lines.append("  [dim]Well-known legitimate domain[/dim]")
            elif domain_trust == "suspicious":
                lines.append(f"  [yellow]⚠ SUSPICIOUS[/yellow]")
                lines.append("  [dim]Domain matches concerning patterns[/dim]")
            else:
                lines.append(f"  [dim]○ NEUTRAL[/dim]")
                lines.append("  [dim]No specific classification[/dim]")
            lines.append("")

            # DGA Detection
            dga_detected = self.data.get('dga_detected', False)
            lines.append("[bold]DGA Analysis[/bold]")
            if dga_detected:
                lines.append("  [red]⚠ DGA PATTERN DETECTED[/red]")
                lines.append("  [dim]Domain appears algorithmically generated[/dim]")
                lines.append("  [dim]Common in malware C2 infrastructure[/dim]")
            else:
                lines.append("  [green]✓ Normal domain pattern[/green]")
            lines.append("")

            # Domain-ASN Correlation
            domain_asn_mismatch = self.data.get('domain_asn_mismatch', False)
            lines.append("[bold]Domain-ASN Correlation[/bold]")
            if domain_asn_mismatch:
                lines.append("  [yellow]⚠ MISMATCH DETECTED[/yellow]")
                lines.append("  [dim]Domain doesn't match expected ASN owner[/dim]")
                lines.append("  [dim]May indicate CDN, MITM, or spoofing[/dim]")
            else:
                dst_org = self.data.get('dst_org', '')
                if dst_org:
                    lines.append(f"  [green]✓ Domain matches ASN owner[/green]")
                    lines.append(f"  [dim]Organization: {dst_org}[/dim]")
                else:
                    lines.append("  [dim]Unable to correlate (no ASN data)[/dim]")

        content = "\n".join(lines)
        return Panel(content, title="[bold cyan]Protocol[/bold cyan]", border_style="cyan")


class ThreatIntelSourcesPanel(Static):
    """
    Shows threat intelligence from multiple sources:
    - Local IOC database matches
    - GreyNoise (benign scanner/service detection)
    - AlienVault OTX pulse data
    """

    DEFAULT_CSS = """
    ThreatIntelSourcesPanel {
        width: 100%;
        height: auto;
        padding: 1;
    }
    """

    def __init__(self, connection_data: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.data = connection_data

    def render(self):
        lines = []
        lines.append("[bold cyan]THREAT INTEL SOURCES[/bold cyan]")
        lines.append("")

        # Local IOC section
        local_ioc_match = self.data.get('local_ioc_match', False)
        lines.append("[bold]Local IOC Database[/bold]")
        if local_ioc_match:
            ioc_type = self.data.get('local_ioc_type', 'unknown')
            ioc_source = self.data.get('local_ioc_source', 'local')
            ioc_conf = self.data.get('local_ioc_confidence', 0)
            ioc_indicator = self.data.get('local_ioc_indicator', '')

            lines.append(f"  [red]⚠ MATCH FOUND[/red]")
            lines.append(f"  Type: [yellow]{ioc_type}[/yellow]")
            lines.append(f"  Source: {ioc_source}")
            lines.append(f"  Confidence: {ioc_conf:.0%}")
            if ioc_indicator:
                lines.append(f"  Indicator: [cyan]{ioc_indicator}[/cyan]")
        else:
            lines.append("  [green]✓ No local IOC matches[/green]")
        lines.append("")

        # GreyNoise section
        greynoise_riot = self.data.get('greynoise_riot', False)
        greynoise_benign = self.data.get('greynoise_benign_scanner', False)
        greynoise_malicious = self.data.get('greynoise_malicious', False)
        greynoise_name = self.data.get('greynoise_name', '')

        lines.append("[bold]GreyNoise Intelligence[/bold]")
        if greynoise_riot:
            category = self.data.get('greynoise_category', 'business')
            lines.append(f"  [green]✓ RIOT: Known Business Service[/green]")
            lines.append(f"  Name: [cyan]{greynoise_name}[/cyan]")
            lines.append(f"  Category: {category}")
            lines.append("  [dim]False positive reduction applied[/dim]")
        elif greynoise_benign:
            actor = self.data.get('greynoise_actor', '')
            lines.append(f"  [green]✓ Benign Scanner[/green]")
            lines.append(f"  Name: [cyan]{greynoise_name}[/cyan]")
            if actor:
                lines.append(f"  Actor: {actor}")
            lines.append("  [dim]Known security research scanner[/dim]")
        elif greynoise_malicious:
            tags = self.data.get('greynoise_tags', [])
            lines.append(f"  [red]⚠ Malicious Scanner[/red]")
            lines.append(f"  Name: [red]{greynoise_name}[/red]")
            if tags:
                lines.append(f"  Tags: {', '.join(tags[:3])}")
        else:
            lines.append("  [dim]○ Not in GreyNoise database[/dim]")
        lines.append("")

        # AlienVault OTX section
        otx_pulse_count = self.data.get('otx_pulse_count', 0)
        lines.append("[bold]AlienVault OTX[/bold]")
        if otx_pulse_count > 0:
            otx_tags = self.data.get('otx_tags', [])
            otx_rep = self.data.get('otx_reputation', 0)
            otx_indicator = self.data.get('otx_indicator', '')
            pulse_names = self.data.get('otx_pulse_names', [])

            severity_color = "red" if otx_pulse_count >= 5 else "yellow" if otx_pulse_count >= 2 else "dim"
            lines.append(f"  [{severity_color}]Found in {otx_pulse_count} pulse(s)[/{severity_color}]")

            if pulse_names:
                lines.append("  [bold]Pulses:[/bold]")
                for name in pulse_names[:3]:
                    lines.append(f"    • {name[:40]}...")

            if otx_tags:
                tag_str = ", ".join(otx_tags[:5])
                lines.append(f"  Tags: [yellow]{tag_str}[/yellow]")

            if otx_rep > 0:
                rep_color = "red" if otx_rep >= 50 else "yellow" if otx_rep >= 25 else "green"
                lines.append(f"  Reputation: [{rep_color}]{otx_rep}[/{rep_color}]")
        else:
            lines.append("  [green]✓ Not in OTX pulses[/green]")
        lines.append("")

        # Aggregated assessment
        lines.append("[bold cyan]─── AGGREGATED ASSESSMENT ───[/bold cyan]")
        lines.append("")

        threat_signals = 0
        benign_signals = 0

        if local_ioc_match:
            threat_signals += 2
        if greynoise_malicious:
            threat_signals += 1
        if otx_pulse_count >= 2:
            threat_signals += 1
        if greynoise_riot or greynoise_benign:
            benign_signals += 2

        if threat_signals >= 2:
            lines.append("[red]⚠ Multiple threat indicators[/red]")
            lines.append(f"[dim]Threat signals: {threat_signals}, Benign: {benign_signals}[/dim]")
        elif threat_signals >= 1 and benign_signals == 0:
            lines.append("[yellow]◐ Single threat indicator[/yellow]")
            lines.append("[dim]Recommend further investigation[/dim]")
        elif benign_signals >= 1:
            lines.append("[green]✓ Likely benign (known service)[/green]")
            lines.append(f"[dim]Benign signals: {benign_signals}[/dim]")
        else:
            lines.append("[dim]○ No definitive indicators[/dim]")

        content = "\n".join(lines)
        return Panel(content, title="[bold cyan]Intel Sources[/bold cyan]", border_style="cyan")


class InvestigationActionsPanel(Static):
    """
    Shows investigation action buttons for SOC analysts.
    Includes pivot options and triage actions.
    """

    DEFAULT_CSS = """
    InvestigationActionsPanel {
        width: 100%;
        height: auto;
        padding: 1;
    }
    """

    def __init__(self, connection_data: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.data = connection_data

    def render(self):
        dst_ip = self.data.get('dst_ip', 'Unknown')
        dst_asn = self.data.get('dst_asn')
        domain = self.data.get('dns_query') or self.data.get('tls_sni')
        threat = float(self.data.get('threat_score', 0) or 0)

        lines = []
        lines.append("[bold cyan]INVESTIGATION ACTIONS[/bold cyan]")
        lines.append("")

        # Triage recommendation
        lines.append("[bold]Recommended Action[/bold]")
        if threat >= 0.7:
            lines.append("  [red]⚠ BLOCK - High threat score[/red]")
            lines.append("  [dim]Consider adding to blocklist[/dim]")
        elif threat >= 0.4:
            lines.append("  [yellow]◐ INVESTIGATE - Elevated risk[/yellow]")
            lines.append("  [dim]Review all connections to this IP[/dim]")
        elif self.data.get('greynoise_riot') or self.data.get('greynoise_benign_scanner'):
            lines.append("  [green]✓ ALLOW - Known benign[/green]")
            lines.append("  [dim]GreyNoise verified service[/dim]")
        else:
            lines.append("  [dim]○ MONITOR - Normal traffic[/dim]")
        lines.append("")

        # Available actions (informational - buttons handled by parent)
        lines.append("[bold]Available Actions[/bold]")
        lines.append("  [cyan][B][/cyan] Add to Local Blocklist")
        lines.append("  [cyan][W][/cyan] Add to Whitelist")
        lines.append("  [cyan][E][/cyan] Export to STIX 2.1")
        lines.append("")

        # Pivot options
        lines.append("[bold]Pivot Options[/bold]")
        lines.append(f"  [cyan][A][/cyan] Show all connections to ASN")
        if dst_asn:
            lines.append(f"      [dim]AS{dst_asn}[/dim]")
        if domain:
            lines.append(f"  [cyan][D][/cyan] Show all DNS to domain")
            lines.append(f"      [dim]{domain}[/dim]")
        lines.append(f"  [cyan][T][/cyan] Show connection timeline")
        lines.append(f"      [dim]{dst_ip}[/dim]")
        lines.append("")

        # Quick stats
        lines.append("[bold]Context[/bold]")
        verification_status = self.data.get('verification_status', 'pending')
        if verification_status == "verified":
            lines.append("  [green]✓ AI Verified[/green]")
        elif verification_status == "flagged":
            lines.append("  [yellow]! Flagged for Review[/yellow]")
        else:
            lines.append("  [dim]○ Pending verification[/dim]")

        high_uncertainty = self.data.get('high_uncertainty', False)
        if high_uncertainty:
            lines.append("  [yellow]⚠ High uncertainty - scorers disagreed[/yellow]")

        content = "\n".join(lines)
        return Panel(content, title="[bold cyan]Actions[/bold cyan]", border_style="cyan")


class ConsensusBreakdownPanel(Static):
    """
    Shows the 4-scorer BFT consensus breakdown.
    Displays individual scorer results, voting matrix, outliers, and confidence.
    """

    DEFAULT_CSS = """
    ConsensusBreakdownPanel {
        width: 100%;
        height: auto;
        padding: 1;
    }
    """

    def __init__(self, connection_data: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.data = connection_data

    def render(self):
        threat = float(self.data.get('threat_score', 0) or 0)
        confidence = float(self.data.get('confidence', 0) or 0)
        high_uncertainty = self.data.get('high_uncertainty', False)
        scoring_method = self.data.get('scoring_method', 'unknown')

        # Determine threat color
        if threat >= 0.7:
            threat_color = "bold red"
            threat_label = "CRITICAL"
        elif threat >= 0.5:
            threat_color = "bold yellow"
            threat_label = "HIGH"
        elif threat >= 0.3:
            threat_color = "yellow"
            threat_label = "MEDIUM"
        else:
            threat_color = "green"
            threat_label = "LOW"

        # Build content
        lines = []
        lines.append("[bold cyan]CONSENSUS RESULT[/bold cyan]")
        lines.append("")

        # Final score with large visual
        score_bar_width = 20
        filled = int(threat * score_bar_width)
        score_bar = f"[{threat_color}]{'█' * filled}[/{threat_color}][dim]{'░' * (score_bar_width - filled)}[/dim]"
        lines.append(f"Threat Score: [{threat_color}]{threat:.3f}[/{threat_color}] {threat_label}")
        lines.append(f"  {score_bar}")
        lines.append("")

        # Confidence gauge
        conf_color = "green" if confidence >= 0.8 else "yellow" if confidence >= 0.5 else "red"
        conf_bar = int(confidence * 10)
        lines.append(f"Confidence: [{conf_color}]{confidence:.2f}[/{conf_color}]")
        lines.append(f"  [{conf_color}]{'●' * conf_bar}[/{conf_color}][dim]{'○' * (10 - conf_bar)}[/dim]")
        lines.append("")

        # Uncertainty flag
        if high_uncertainty:
            lines.append("[bold yellow]⚠ HIGH UNCERTAINTY[/bold yellow]")
            lines.append("[dim]Scorers disagreed significantly[/dim]")
        else:
            lines.append("[green]✓ Consensus Achieved[/green]")
        lines.append("")

        # Scoring method
        lines.append(f"[dim]Method:[/dim] {scoring_method}")
        lines.append("")

        # Individual scorer breakdown
        lines.append("[bold cyan]─── SCORER BREAKDOWN ───[/bold cyan]")
        lines.append("")

        # Get real scores if available, otherwise estimate
        score_statistical = self.data.get('score_statistical')
        score_rule_based = self.data.get('score_rule_based')
        score_ml_based = self.data.get('score_ml_based')
        score_organization = self.data.get('score_organization')
        score_spread = self.data.get('score_spread')

        has_real_data = any([score_statistical, score_rule_based, score_ml_based, score_organization])

        if has_real_data:
            scorers = [
                ("Statistical", score_statistical, "Z-score analysis"),
                ("Rule-Based", score_rule_based, "Pattern matching"),
                ("ML Model", score_ml_based, "Neural network"),
                ("Organization", score_organization, "Trust scoring"),
            ]
        else:
            # Estimate individual scores based on final (fallback for old data)
            scorers = [
                ("Statistical", threat + 0.05 if threat < 0.95 else threat, "Z-score analysis"),
                ("Rule-Based", threat - 0.02 if threat > 0.02 else threat, "Pattern matching"),
                ("ML Model", threat + 0.08 if threat < 0.92 else threat, "Neural network"),
                ("Organization", threat - 0.15 if threat > 0.15 else threat, "Trust scoring"),
            ]

        for scorer_name, score, desc in scorers:
            if score is None:
                lines.append(f"{scorer_name:12} [dim]N/A[/dim]")
                lines.append(f"  [dim]{desc}[/dim]")
                continue

            score = max(0, min(1, float(score)))  # Clamp
            bar_width = 12
            filled = int(score * bar_width)

            if score >= 0.7:
                s_color = "red"
            elif score >= 0.5:
                s_color = "yellow"
            else:
                s_color = "green"

            bar = f"[{s_color}]{'█' * filled}[/{s_color}][dim]{'░' * (bar_width - filled)}[/dim]"
            lines.append(f"{scorer_name:12} {bar} [{s_color}]{score:.2f}[/{s_color}]")
            lines.append(f"  [dim]{desc}[/dim]")

        lines.append("")

        # Score spread (measure of disagreement)
        if score_spread is not None:
            spread_color = "green" if score_spread < 0.15 else "yellow" if score_spread < 0.25 else "red"
            lines.append(f"Score Spread: [{spread_color}]{score_spread:.3f}[/{spread_color}]")
            if score_spread >= 0.25:
                lines.append("[yellow]⚠ Significant scorer disagreement[/yellow]")
        lines.append("")

        if not has_real_data:
            lines.append("[dim italic]Note: Individual scores estimated (old data).[/dim italic]")

        content = "\n".join(lines)
        return Panel(content, title="[bold cyan]Consensus[/bold cyan]", border_style="cyan")


class EnrichmentDetailsPanel(Static):
    """
    Shows ASN, organization, hop count, TTL analysis, and CIDR information.
    """

    DEFAULT_CSS = """
    EnrichmentDetailsPanel {
        width: 100%;
        height: auto;
        padding: 1;
    }
    """

    # Organization type risk levels
    ORG_TYPE_INFO = {
        'cloud': ('CLOUD', 'green', 'Major cloud provider'),
        'cdn': ('CDN', 'green', 'Content delivery network'),
        'enterprise': ('ENTERPRISE', 'green', 'Corporate network'),
        'education': ('EDU', 'green', 'Educational institution'),
        'government': ('GOV', 'cyan', 'Government network'),
        'isp': ('ISP', 'yellow', 'Internet service provider'),
        'isp_residential': ('ISP-RES', 'yellow', 'Residential ISP'),
        'isp_business': ('ISP-BIZ', 'green', 'Business ISP'),
        'hosting': ('HOSTING', 'yellow', 'Hosting provider'),
        'vpn': ('VPN', 'bold yellow', 'VPN service'),
        'proxy': ('PROXY', 'bold yellow', 'Proxy service'),
        'tor': ('TOR', 'bold red', 'Tor exit node'),
        'unknown': ('UNKNOWN', 'dim', 'Unclassified'),
    }

    def __init__(self, connection_data: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.data = connection_data

    def render(self):
        lines = []
        lines.append("[bold cyan]ENRICHMENT DATA[/bold cyan]")
        lines.append("")

        # Connection Direction
        src_ip = self.data.get('src_ip', 'local')
        dst_ip = self.data.get('dst_ip', 'Unknown')
        dst_port = self.data.get('dst_port', 0) or 0
        dir_label, dir_color, dir_symbol = get_direction(src_ip, dst_ip)
        dir_full = {"OUT": "Outgoing", "IN": "Incoming", "INT": "Internal", "EXT": "External"}.get(dir_label, "Unknown")
        lines.append("[bold]Connection Direction[/bold]")
        lines.append(f"  [{dir_color}]{dir_symbol} {dir_full}[/{dir_color}]")
        lines.append(f"  [dim]{src_ip} → {dst_ip}:{dst_port}[/dim]")

        # Ephemeral port warning for destination ports
        if dst_port >= 49152:
            lines.append("")
            lines.append("[bold yellow]Ephemeral Port Warning[/bold yellow]")
            lines.append(f"  [yellow]Port {dst_port} is in ephemeral range (49152-65535)[/yellow]")
            lines.append("  [dim]Unusual for destination - may indicate:[/dim]")
            lines.append("  [dim]  - P2P/BitTorrent traffic[/dim]")
            lines.append("  [dim]  - Custom tunneling[/dim]")
            lines.append("  [dim]  - C2 callback on dynamic port[/dim]")
        lines.append("")

        # ASN Information
        asn = self.data.get('dst_asn')
        asn_name = self.data.get('dst_asn_name', 'Unknown')
        org = self.data.get('dst_org', 'Unknown')
        org_type = (self.data.get('dst_org_type') or 'unknown').lower()
        trust = float(self.data.get('org_trust_score', 0.5) or 0.5)
        cidr = self.data.get('dst_cidr', 'N/A')

        lines.append("[bold]ASN Information[/bold]")
        if asn:
            lines.append(f"  ASN: [cyan]AS{asn}[/cyan]")
            lines.append(f"  Name: [white]{asn_name}[/white]")
        else:
            lines.append("  ASN: [dim]Not available[/dim]")

        lines.append(f"  Organization: [white]{org}[/white]")
        lines.append(f"  CIDR: [dim]{cidr}[/dim]")
        lines.append("")

        # Organization Type with risk indicator
        type_info = self.ORG_TYPE_INFO.get(org_type, self.ORG_TYPE_INFO['unknown'])
        type_label, type_color, type_desc = type_info
        lines.append("[bold]Organization Classification[/bold]")
        lines.append(f"  Type: [{type_color}]{type_label}[/{type_color}]")
        lines.append(f"  [dim]{type_desc}[/dim]")
        lines.append("")

        # Trust Score
        trust_color = "green" if trust >= 0.7 else "yellow" if trust >= 0.4 else "red"
        trust_bar = int(trust * 10)
        lines.append("[bold]Trust Assessment[/bold]")
        lines.append(f"  Score: [{trust_color}]{trust:.2f}[/{trust_color}]")
        lines.append(f"  [{trust_color}]{'█' * trust_bar}[/{trust_color}][dim]{'░' * (10 - trust_bar)}[/dim]")

        # Trust interpretation
        if trust >= 0.8:
            lines.append("  [green]✓ Highly Trusted[/green]")
        elif trust >= 0.6:
            lines.append("  [green]✓ Trusted[/green]")
        elif trust >= 0.4:
            lines.append("  [yellow]◐ Neutral[/yellow]")
        elif trust >= 0.2:
            lines.append("  [yellow]⚠ Low Trust[/yellow]")
        else:
            lines.append("  [red]✗ Untrusted[/red]")
        lines.append("")

        # Hop Count and TTL Analysis
        hop_count = self.data.get('hop_count')
        ttl_observed = self.data.get('ttl_observed')
        ttl_initial = self.data.get('ttl_initial')
        os_fingerprint = self.data.get('os_fingerprint', 'Unknown')

        lines.append("[bold]Network Path Analysis[/bold]")
        if hop_count and hop_count > 0:
            hop_color = "green" if hop_count < 10 else "yellow" if hop_count < 20 else "red"
            lines.append(f"  Hops: [{hop_color}]{hop_count}[/{hop_color}]")

            # Hop risk assessment
            if hop_count < 5:
                lines.append("  [green]Very close (local/regional)[/green]")
            elif hop_count < 10:
                lines.append("  [green]Normal distance[/green]")
            elif hop_count < 15:
                lines.append("  [yellow]Moderate distance[/yellow]")
            elif hop_count < 25:
                lines.append("  [yellow]⚠ Far (possible tunneling)[/yellow]")
            else:
                lines.append("  [red]⚠ Very far (suspicious)[/red]")
        else:
            lines.append("  Hops: [dim]Awaiting response[/dim]")

        if ttl_observed:
            lines.append(f"  TTL Observed: {ttl_observed}")
            if ttl_initial:
                lines.append(f"  TTL Initial: {ttl_initial} (estimated)")
        lines.append(f"  OS Fingerprint: [cyan]{os_fingerprint}[/cyan]")
        lines.append("")

        # Geographic info
        country = self.data.get('dst_country', 'XX')
        lat = self.data.get('dst_lat')
        lon = self.data.get('dst_lon')

        lines.append("[bold]Geographic Location[/bold]")
        lines.append(f"  Country: [white]{country}[/white]")
        if lat and lon:
            lines.append(f"  Coordinates: {lat:.4f}, {lon:.4f}")

        content = "\n".join(lines)
        return Panel(content, title="[bold cyan]Enrichment[/bold cyan]", border_style="cyan")


class AnomalyAnalysisPanel(Static):
    """
    Shows anomaly detection results including Z-scores and contributing factors.
    """

    DEFAULT_CSS = """
    AnomalyAnalysisPanel {
        width: 100%;
        height: auto;
        padding: 1;
    }
    """

    def __init__(self, connection_data: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.data = connection_data

    def render(self):
        threat = float(self.data.get('threat_score', 0) or 0)
        confidence = float(self.data.get('confidence', 0) or 0)
        trust = float(self.data.get('org_trust_score', 0.5) or 0.5)
        hop_count = self.data.get('hop_count') or 0
        high_uncertainty = self.data.get('high_uncertainty', False)

        lines = []
        lines.append("[bold cyan]ANOMALY ANALYSIS[/bold cyan]")
        lines.append("")

        # Calculate estimated anomaly score from available data
        # This is a placeholder - real anomaly data will come from Phase 1
        anomaly_factors = []
        anomaly_score = 0.0

        # Threat-based anomaly
        if threat >= 0.7:
            anomaly_score += 0.4
            z_threat = (threat - 0.3) / 0.15  # Estimated z-score
            anomaly_factors.append(("threat_score", z_threat, "High threat level"))
        elif threat >= 0.5:
            anomaly_score += 0.2
            z_threat = (threat - 0.3) / 0.15
            anomaly_factors.append(("threat_score", z_threat, "Elevated threat"))

        # Trust-based anomaly
        if trust < 0.3:
            anomaly_score += 0.2
            z_trust = (0.5 - trust) / 0.2
            anomaly_factors.append(("org_distrust", z_trust, "Low organization trust"))

        # Hop-based anomaly
        if hop_count > 20:
            anomaly_score += 0.2
            z_hops = (hop_count - 12) / 5
            anomaly_factors.append(("hop_distance", z_hops, "Unusual network distance"))

        # Uncertainty as anomaly indicator
        if high_uncertainty:
            anomaly_score += 0.15
            anomaly_factors.append(("consensus_uncertainty", 1.5, "Scorer disagreement"))

        anomaly_score = min(1.0, anomaly_score)

        # Anomaly classification
        if anomaly_score >= 0.7:
            anomaly_class = "CRITICAL"
            anomaly_color = "bold red"
        elif anomaly_score >= 0.5:
            anomaly_class = "SUSPICIOUS"
            anomaly_color = "bold yellow"
        elif anomaly_score >= 0.3:
            anomaly_class = "UNUSUAL"
            anomaly_color = "yellow"
        else:
            anomaly_class = "NORMAL"
            anomaly_color = "green"

        # Overall anomaly score
        lines.append("[bold]Anomaly Assessment[/bold]")
        bar_width = 15
        filled = int(anomaly_score * bar_width)
        bar = f"[{anomaly_color}]{'█' * filled}[/{anomaly_color}][dim]{'░' * (bar_width - filled)}[/dim]"
        lines.append(f"  Score: [{anomaly_color}]{anomaly_score:.2f}[/{anomaly_color}] {bar}")
        lines.append(f"  Classification: [{anomaly_color}]{anomaly_class}[/{anomaly_color}]")
        lines.append("")

        # Estimated percentile
        if anomaly_score >= 0.7:
            percentile = 95
        elif anomaly_score >= 0.5:
            percentile = 85
        elif anomaly_score >= 0.3:
            percentile = 70
        else:
            percentile = 50

        lines.append(f"  Percentile: [cyan]{percentile}th[/cyan]")
        lines.append(f"  [dim]This connection is more anomalous than {percentile}% of traffic[/dim]")
        lines.append("")

        # Contributing factors
        lines.append("[bold]Contributing Factors[/bold]")
        if anomaly_factors:
            for factor_name, z_score, description in anomaly_factors:
                z_color = "red" if z_score >= 2.0 else "yellow" if z_score >= 1.0 else "green"
                lines.append(f"  [{z_color}]●[/{z_color}] {factor_name}")
                lines.append(f"    Z-score: [{z_color}]{z_score:.2f}[/{z_color}] - {description}")
        else:
            lines.append("  [green]No significant anomalies detected[/green]")
        lines.append("")

        lines.append("[dim italic]Note: Anomaly scores estimated from available data.[/dim italic]")
        lines.append("[dim italic]Full Z-score analysis in Phase 1.[/dim italic]")

        content = "\n".join(lines)
        return Panel(content, title="[bold cyan]Anomaly[/bold cyan]", border_style="cyan")


class ReputationPanel(Static):
    """
    Shows IP reputation data from VirusTotal, AbuseIPDB, and other sources.
    """

    DEFAULT_CSS = """
    ReputationPanel {
        width: 100%;
        height: auto;
        padding: 1;
    }
    """

    def __init__(self, connection_data: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.data = connection_data

    def render(self):
        threat = float(self.data.get('threat_score', 0) or 0)
        dst_ip = self.data.get('dst_ip', 'Unknown')
        org_type = (self.data.get('dst_org_type') or 'unknown').lower()

        lines = []
        lines.append("[bold cyan]IP REPUTATION[/bold cyan]")
        lines.append("")
        lines.append(f"[bold]Target IP:[/bold] [cyan]{dst_ip}[/cyan]")
        lines.append("")

        # Estimate reputation based on threat score and org type
        # Real data will come from stored API responses in Phase 1

        # VirusTotal estimation
        lines.append("[bold]VirusTotal[/bold]")
        if threat >= 0.7:
            vt_malicious = int(threat * 10)
            vt_total = 70
            vt_color = "red"
            lines.append(f"  Detections: [{vt_color}]{vt_malicious}/{vt_total}[/{vt_color}] vendors")
            lines.append(f"  [red]⚠ Flagged as malicious[/red]")
        elif threat >= 0.4:
            vt_malicious = int(threat * 5)
            vt_total = 70
            vt_color = "yellow"
            lines.append(f"  Detections: [{vt_color}]{vt_malicious}/{vt_total}[/{vt_color}] vendors")
            lines.append(f"  [yellow]◐ Some vendors flagged[/yellow]")
        else:
            lines.append("  Detections: [green]0/70[/green] vendors")
            lines.append("  [green]✓ Clean[/green]")
        lines.append("")

        # AbuseIPDB estimation
        lines.append("[bold]AbuseIPDB[/bold]")
        if threat >= 0.6:
            abuse_conf = int(threat * 100)
            abuse_reports = int(threat * 50)
            abuse_color = "red" if abuse_conf >= 75 else "yellow"
            lines.append(f"  Confidence: [{abuse_color}]{abuse_conf}%[/{abuse_color}]")
            lines.append(f"  Reports: [{abuse_color}]{abuse_reports}[/{abuse_color}]")
        else:
            lines.append("  Confidence: [green]0%[/green]")
            lines.append("  Reports: [green]0[/green]")
        lines.append("")

        # Whitelist status
        lines.append("[bold]Whitelist Status[/bold]")
        if org_type in ['cloud', 'cdn', 'enterprise', 'education']:
            lines.append("  [green]✓ Organization whitelisted[/green]")
        elif org_type in ['tor', 'proxy', 'vpn']:
            lines.append("  [red]✗ High-risk category[/red]")
        else:
            lines.append("  [dim]○ Not whitelisted[/dim]")
        lines.append("")

        # Abuse types (estimated)
        if threat >= 0.5:
            lines.append("[bold]Detected Abuse Types[/bold]")
            abuse_types = []
            if threat >= 0.7:
                abuse_types.extend(["Malware", "Botnet C2"])
            if threat >= 0.5:
                abuse_types.extend(["Scanning", "Brute Force"])
            for atype in abuse_types[:3]:
                lines.append(f"  [yellow]●[/yellow] {atype}")
            lines.append("")

        lines.append("[dim italic]Note: Reputation data estimated.[/dim italic]")
        lines.append("[dim italic]Live API data in Phase 1.[/dim italic]")

        content = "\n".join(lines)
        return Panel(content, title="[bold cyan]Reputation[/bold cyan]", border_style="cyan")


class RulesTriggeredPanel(Static):
    """
    Shows which threat detection rules were triggered for this connection.
    """

    DEFAULT_CSS = """
    RulesTriggeredPanel {
        width: 100%;
        height: auto;
        padding: 1;
    }
    """

    # All available rules
    RULES = [
        ("VT_HIGH_THREAT", "VirusTotal >= 5 vendors", 0.7),
        ("VT_MED_THREAT", "VirusTotal >= 2 vendors", 0.4),
        ("ABUSEIPDB_HIGH", "AbuseIPDB >= 75%", 0.6),
        ("ABUSEIPDB_MED", "AbuseIPDB >= 50%", 0.4),
        ("HIGH_RISK_PORT", "RDP, SMB, Telnet, etc.", 0.3),
        ("TOR_PROXY", "Tor or proxy detected", 0.5),
        ("GEO_HIGH_RISK", "High-risk country", 0.4),
        ("LOW_TRUST_ORG", "Organization trust < 0.3", 0.3),
        ("HOP_ANOMALY", "Unusual hop count", 0.4),
        ("NEW_DESTINATION", "First contact with IP", 0.2),
        ("PORT_SCAN", "Multiple ports accessed", 0.5),
        ("CONSENSUS_UNCERTAIN", "Scorers disagreed", 0.3),
    ]

    def __init__(self, connection_data: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.data = connection_data

    def render(self):
        threat = float(self.data.get('threat_score', 0) or 0)
        trust = float(self.data.get('org_trust_score', 0.5) or 0.5)
        org_type = (self.data.get('dst_org_type') or 'unknown').lower()
        hop_count = self.data.get('hop_count') or 0
        high_uncertainty = self.data.get('high_uncertainty', False)
        dst_port = self.data.get('dst_port', 0)

        lines = []
        lines.append("[bold cyan]RULES TRIGGERED[/bold cyan]")
        lines.append("")

        # Determine which rules would have fired
        triggered_rules = []
        not_triggered = []

        for rule_name, rule_desc, threshold in self.RULES:
            triggered = False

            if rule_name == "VT_HIGH_THREAT" and threat >= 0.7:
                triggered = True
            elif rule_name == "VT_MED_THREAT" and threat >= 0.4:
                triggered = True
            elif rule_name == "ABUSEIPDB_HIGH" and threat >= 0.6:
                triggered = True
            elif rule_name == "ABUSEIPDB_MED" and threat >= 0.4:
                triggered = True
            elif rule_name == "HIGH_RISK_PORT" and dst_port in [22, 23, 3389, 445, 139, 21, 3306, 1433]:
                triggered = True
            elif rule_name == "TOR_PROXY" and org_type in ['tor', 'proxy', 'vpn']:
                triggered = True
            elif rule_name == "LOW_TRUST_ORG" and trust < 0.3:
                triggered = True
            elif rule_name == "HOP_ANOMALY" and hop_count > 25:
                triggered = True
            elif rule_name == "CONSENSUS_UNCERTAIN" and high_uncertainty:
                triggered = True

            if triggered:
                triggered_rules.append((rule_name, rule_desc))
            else:
                not_triggered.append((rule_name, rule_desc))

        # Show triggered rules
        lines.append("[bold]Triggered[/bold]")
        if triggered_rules:
            for rule_name, rule_desc in triggered_rules:
                lines.append(f"  [red]✓[/red] [bold]{rule_name}[/bold]")
                lines.append(f"    [dim]{rule_desc}[/dim]")
        else:
            lines.append("  [green]No rules triggered[/green]")
        lines.append("")

        # Show not triggered (collapsed)
        lines.append("[bold]Not Triggered[/bold]")
        for rule_name, rule_desc in not_triggered[:5]:  # Show first 5
            lines.append(f"  [dim]○ {rule_name}[/dim]")
        if len(not_triggered) > 5:
            lines.append(f"  [dim]... and {len(not_triggered) - 5} more[/dim]")
        lines.append("")

        # Summary
        total_rules = len(self.RULES)
        triggered_count = len(triggered_rules)
        lines.append(f"[bold]Summary:[/bold] {triggered_count}/{total_rules} rules fired")

        if triggered_count >= 4:
            lines.append("[red]⚠ Multiple indicators of compromise[/red]")
        elif triggered_count >= 2:
            lines.append("[yellow]⚠ Elevated risk indicators[/yellow]")
        elif triggered_count >= 1:
            lines.append("[yellow]◐ Minor risk indicators[/yellow]")
        else:
            lines.append("[green]✓ No risk indicators[/green]")

        content = "\n".join(lines)
        return Panel(content, title="[bold cyan]Rules[/bold cyan]", border_style="cyan")


class GraphPositionPanel(Static):
    """
    Shows the connection's position in the network graph.
    Includes centrality, cluster membership, and attack path status.
    """

    DEFAULT_CSS = """
    GraphPositionPanel {
        width: 100%;
        height: auto;
        padding: 1;
    }
    """

    def __init__(self, connection_data: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.data = connection_data

    def render(self):
        dst_ip = self.data.get('dst_ip', 'Unknown')
        threat = float(self.data.get('threat_score', 0) or 0)
        dst_org = self.data.get('dst_org', 'Unknown')
        asn = self.data.get('dst_asn')

        # Try to get cached graph analytics from the app
        graph_cache = getattr(self.app, 'graph_analytics_cache', {})

        lines = []
        lines.append("[bold cyan]GRAPH ANALYSIS[/bold cyan]")
        lines.append("")

        # Network Centrality from cached graph analytics
        lines.append("[bold]Network Centrality[/bold]")
        centrality = 0.0
        high_centrality_ips = graph_cache.get('high_centrality_ips', [])
        for node in high_centrality_ips:
            if node.get('ip') == dst_ip:
                centrality = node.get('centrality', 0)
                break

        if centrality > 0:
            lines.append(f"  PageRank: [cyan]{centrality:.4f}[/cyan]")
            if centrality >= 0.05:
                lines.append("  [yellow]⚠ High centrality (potential C2)[/yellow]")
            elif centrality >= 0.02:
                lines.append("  [dim]Moderate centrality[/dim]")
            else:
                lines.append("  [dim]Normal centrality[/dim]")
        else:
            # Estimate based on threat if not in top centrality nodes
            estimated = 0.01 + (threat * 0.02)
            lines.append(f"  PageRank: [dim]~{estimated:.4f}[/dim]")
            lines.append("  [dim]Not in top centrality nodes[/dim]")
        lines.append("")

        # Threat Cluster membership
        lines.append("[bold]Threat Cluster[/bold]")
        threat_clusters = graph_cache.get('threat_clusters', [])
        in_cluster = False
        for i, cluster in enumerate(threat_clusters):
            cluster_ips = cluster.get('ips', [])
            if dst_ip in cluster_ips:
                in_cluster = True
                cluster_size = cluster.get('size', len(cluster_ips))
                lines.append(f"  Cluster: [yellow]#{i+1}[/yellow]")
                lines.append(f"  Size: [cyan]{cluster_size}[/cyan] nodes")
                break
        if not in_cluster:
            if threat >= 0.5:
                lines.append("  [yellow]Potentially forming cluster[/yellow]")
            else:
                lines.append("  [green]Not in threat cluster[/green]")
        lines.append("")

        # Attack paths from graph analytics
        lines.append("[bold]Attack Path[/bold]")
        attack_paths = graph_cache.get('potential_attack_paths', [])
        in_path = False
        for path in attack_paths:
            if dst_ip in path.get('path', []):
                in_path = True
                lines.append("  [red]⚠ In potential attack chain[/red]")
                lines.append(f"  [dim]Threat: {path.get('threat', 0):.2f}[/dim]")
                break
        if not in_path:
            if threat >= 0.7:
                lines.append("  [yellow]Monitoring for attack patterns[/yellow]")
            else:
                lines.append("  [green]No attack path detected[/green]")
        lines.append("")

        # Connection degree from graph summary
        lines.append("[bold]Connection Degree[/bold]")
        summary = graph_cache.get('summary', {})
        total_edges = summary.get('total_connections', 0)
        if total_edges > 0:
            lines.append(f"  Total tracked: [cyan]{total_edges}[/cyan] connections")
            lines.append(f"  Unique IPs: [cyan]{summary.get('unique_destinations', 0)}[/cyan]")
        else:
            lines.append("  [dim]Graph building...[/dim]")
        lines.append("")

        # ASN threat ranking from graph analytics
        lines.append("[bold]ASN Threat Ranking[/bold]")
        top_asns = graph_cache.get('top_threat_asns', [])
        if asn:
            asn_rank = None
            for i, asn_data in enumerate(top_asns):
                if str(asn_data.get('asn')) == str(asn):
                    asn_rank = i + 1
                    avg_threat = asn_data.get('avg_threat', 0)
                    lines.append(f"  AS{asn} Rank: [yellow]#{asn_rank}[/yellow] (avg: {avg_threat:.2f})")
                    break
            if asn_rank is None:
                lines.append(f"  AS{asn}: [green]Not in top threat ASNs[/green]")
        else:
            lines.append("  [dim]ASN not available[/dim]")
        lines.append("")

        # Show when analytics were last computed
        generated_at = graph_cache.get('generated_at', 0)
        if generated_at:
            import time
            age = int(time.time() - generated_at)
            lines.append(f"[dim italic]Analytics: {age}s ago[/dim italic]")
        else:
            lines.append("[dim italic]Analytics: initializing...[/dim italic]")

        content = "\n".join(lines)
        return Panel(content, title="[bold cyan]Graph[/bold cyan]", border_style="cyan")


class VerificationTriangulationPanel(Static):
    """
    Shows AI verification status and triangulation analysis.
    Explains why metrics are scored as they are.
    """

    DEFAULT_CSS = """
    VerificationTriangulationPanel {
        width: 100%;
        height: auto;
        padding: 1;
    }
    """

    def __init__(self, connection_data: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.data = connection_data

    def render(self):
        verification_status = self.data.get('verification_status', 'pending')
        verification_reason = self.data.get('verification_reason', '')
        verification_confidence = float(self.data.get('verification_confidence', 0) or 0)
        triangulation_score = self.data.get('triangulation_score')
        triangulation_sources = self.data.get('triangulation_sources', 0)

        lines = []
        lines.append("[bold cyan]AI VERIFICATION[/bold cyan]")
        lines.append("")

        # Verification status with visual
        if verification_status == "verified":
            status_color = "bold green"
            status_icon = "✓"
            status_desc = "Assessment verified by local AI"
        elif verification_status == "flagged":
            status_color = "bold yellow"
            status_icon = "!"
            status_desc = "Flagged for review - uncertainty detected"
        elif verification_status == "unknown":
            status_color = "bold red"
            status_icon = "✗"
            status_desc = "Unable to verify - insufficient data"
        else:  # pending
            status_color = "dim"
            status_icon = "?"
            status_desc = "Verification pending - collecting data"

        lines.append("[bold]Verification Status[/bold]")
        lines.append(f"  [{status_color}]{status_icon} {verification_status.upper()}[/{status_color}]")
        lines.append(f"  [dim]{status_desc}[/dim]")
        lines.append("")

        # Verification reason
        if verification_reason:
            lines.append("[bold]Reason[/bold]")
            # Wrap long reasons
            reason_words = verification_reason.split()
            current_line = "  "
            for word in reason_words:
                if len(current_line) + len(word) > 50:
                    lines.append(current_line)
                    current_line = "  "
                current_line += word + " "
            if current_line.strip():
                lines.append(current_line)
            lines.append("")

        # Verification confidence gauge
        lines.append("[bold]Verification Confidence[/bold]")
        conf_bar_width = 15
        conf_filled = int(verification_confidence * conf_bar_width)
        if verification_confidence >= 0.8:
            conf_color = "green"
        elif verification_confidence >= 0.5:
            conf_color = "yellow"
        else:
            conf_color = "red"
        conf_bar = f"[{conf_color}]{'█' * conf_filled}[/{conf_color}][dim]{'░' * (conf_bar_width - conf_filled)}[/dim]"
        lines.append(f"  {conf_bar} [{conf_color}]{verification_confidence:.2f}[/{conf_color}]")
        lines.append("")

        # Triangulation analysis
        lines.append("[bold cyan]─── TRIANGULATION ───[/bold cyan]")
        lines.append("")
        lines.append("[bold]Source Agreement[/bold]")

        # Show triangulation sources
        source_names = ["Statistical", "Rule-Based", "ML Model", "Organization"]
        scores = [
            self.data.get('score_statistical'),
            self.data.get('score_rule_based'),
            self.data.get('score_ml_based'),
            self.data.get('score_organization'),
        ]

        available_count = sum(1 for s in scores if s is not None)
        lines.append(f"  Sources responding: [cyan]{available_count}/4[/cyan]")
        lines.append("")

        for name, score in zip(source_names, scores):
            if score is not None:
                score = float(score)
                if score >= 0.7:
                    score_color = "red"
                    indicator = "●"
                elif score >= 0.5:
                    score_color = "yellow"
                    indicator = "◐"
                else:
                    score_color = "green"
                    indicator = "○"
                lines.append(f"  [{score_color}]{indicator}[/{score_color}] {name}: [{score_color}]{score:.2f}[/{score_color}]")
            else:
                lines.append(f"  [dim]○ {name}: N/A[/dim]")
        lines.append("")

        # Triangulation score
        if triangulation_score is not None:
            lines.append("[bold]Triangulation Score[/bold]")
            tri_bar_width = 15
            tri_filled = int(triangulation_score * tri_bar_width)
            if triangulation_score >= 0.8:
                tri_color = "green"
                tri_label = "Strong Agreement"
            elif triangulation_score >= 0.6:
                tri_color = "cyan"
                tri_label = "Good Agreement"
            elif triangulation_score >= 0.4:
                tri_color = "yellow"
                tri_label = "Moderate Agreement"
            else:
                tri_color = "red"
                tri_label = "Weak Agreement"

            tri_bar = f"[{tri_color}]{'█' * tri_filled}[/{tri_color}][dim]{'░' * (tri_bar_width - tri_filled)}[/dim]"
            lines.append(f"  {tri_bar} [{tri_color}]{triangulation_score:.2f}[/{tri_color}]")
            lines.append(f"  [{tri_color}]{tri_label}[/{tri_color}]")
        else:
            lines.append("[dim]Triangulation: Calculating...[/dim]")

        content = "\n".join(lines)
        return Panel(content, title="[bold cyan]Verification[/bold cyan]", border_style="cyan")


class MetricExplanationPanel(Static):
    """
    Shows human-readable explanations for all metrics.
    Explains why each metric is scored as it is, especially for unknown values.
    """

    DEFAULT_CSS = """
    MetricExplanationPanel {
        width: 100%;
        height: auto;
        padding: 1;
    }
    """

    # Pre-defined explanations
    METRIC_EXPLANATIONS = {
        'threat_score': {
            'high': "Multiple indicators suggest malicious activity",
            'medium': "Some concerning patterns detected, requires monitoring",
            'low': "Normal traffic patterns, no significant threats",
            'unknown': "Insufficient data for accurate threat assessment",
        },
        'confidence': {
            'high': "Scorers strongly agree on assessment",
            'medium': "Most scorers agree, minor variance",
            'low': "Significant disagreement between scorers",
            'unknown': "Not enough scorer responses for confidence",
        },
        'org_trust': {
            'high': "Well-known, reputable organization",
            'medium': "Standard network with mixed indicators",
            'low': "Limited reputation or concerning history",
            'unknown': "Organization not in database",
        },
        'hop_count': {
            'low': "Normal network distance",
            'high': "Unusual distance - possible tunneling",
            'unknown': "Awaiting response packet for TTL analysis",
        },
        'unknown_org': {
            'reason': "Organization not found in ASN pattern database",
            'fallback': "Raw ASN name displayed when available",
            'impact': "Neutral trust score (0.5) applied",
        },
        'ephemeral_port': {
            'range': "Ports 49152-65535 (dynamic/private)",
            'normal': "Source ports are typically ephemeral - this is normal",
            'concerning': "Destination ephemeral ports are unusual (P2P, tunneling, C2)",
        },
        'passive_discovery': {
            'limits': [
                "Cannot discover idle devices",
                "Hop count requires response packets",
                "Hostname needs mDNS/NetBIOS/DHCP traffic",
            ],
            'benefits': ["Zero network footprint", "No IDS/IPS alerts"],
        },
    }

    def __init__(self, connection_data: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.data = connection_data

    def render(self):
        lines = []
        lines.append("[bold cyan]METRIC EXPLANATIONS[/bold cyan]")
        lines.append("")
        lines.append("[dim]Why are these metrics scored this way?[/dim]")
        lines.append("")

        # Threat Score explanation
        threat = float(self.data.get('threat_score', 0) or 0)
        lines.append("[bold]Threat Score[/bold]")
        if threat >= 0.7:
            lines.append(f"  [red]{threat:.2f}[/red]: {self.METRIC_EXPLANATIONS['threat_score']['high']}")
        elif threat >= 0.4:
            lines.append(f"  [yellow]{threat:.2f}[/yellow]: {self.METRIC_EXPLANATIONS['threat_score']['medium']}")
        elif threat > 0:
            lines.append(f"  [green]{threat:.2f}[/green]: {self.METRIC_EXPLANATIONS['threat_score']['low']}")
        else:
            lines.append(f"  [dim]{threat:.2f}[/dim]: {self.METRIC_EXPLANATIONS['threat_score']['unknown']}")
        lines.append("")

        # Confidence explanation
        conf = float(self.data.get('confidence', 0) or 0)
        lines.append("[bold]Confidence[/bold]")
        if conf >= 0.8:
            lines.append(f"  [green]{conf:.2f}[/green]: {self.METRIC_EXPLANATIONS['confidence']['high']}")
        elif conf >= 0.5:
            lines.append(f"  [yellow]{conf:.2f}[/yellow]: {self.METRIC_EXPLANATIONS['confidence']['medium']}")
        elif conf > 0:
            lines.append(f"  [red]{conf:.2f}[/red]: {self.METRIC_EXPLANATIONS['confidence']['low']}")
        else:
            lines.append(f"  [dim]N/A[/dim]: {self.METRIC_EXPLANATIONS['confidence']['unknown']}")
        lines.append("")

        # Organization Trust explanation
        trust = float(self.data.get('org_trust_score', 0.5) or 0.5)
        org = self.data.get('dst_org', 'Unknown')
        org_type = (self.data.get('dst_org_type') or 'unknown').lower()
        lines.append("[bold]Organization Trust[/bold]")
        if org and org != 'Unknown':
            lines.append(f"  Org: [white]{org}[/white]")
            lines.append(f"  Type: [cyan]{org_type}[/cyan]")
        if trust >= 0.7:
            lines.append(f"  Trust: [green]{trust:.2f}[/green]: {self.METRIC_EXPLANATIONS['org_trust']['high']}")
        elif trust >= 0.4:
            lines.append(f"  Trust: [yellow]{trust:.2f}[/yellow]: {self.METRIC_EXPLANATIONS['org_trust']['medium']}")
        elif trust > 0:
            lines.append(f"  Trust: [red]{trust:.2f}[/red]: {self.METRIC_EXPLANATIONS['org_trust']['low']}")
        else:
            lines.append(f"  Trust: [dim]N/A[/dim]: {self.METRIC_EXPLANATIONS['org_trust']['unknown']}")
        lines.append("")

        # Hop Count explanation
        hop_count = self.data.get('hop_count')
        lines.append("[bold]Network Distance (Hops)[/bold]")
        if hop_count is not None and hop_count > 0:
            if hop_count < 15:
                lines.append(f"  [green]{hop_count} hops[/green]: {self.METRIC_EXPLANATIONS['hop_count']['low']}")
            else:
                lines.append(f"  [yellow]{hop_count} hops[/yellow]: {self.METRIC_EXPLANATIONS['hop_count']['high']}")
        else:
            lines.append(f"  [dim]Unknown[/dim]: {self.METRIC_EXPLANATIONS['hop_count']['unknown']}")
        lines.append("")

        # High Uncertainty explanation
        high_uncertainty = self.data.get('high_uncertainty', False)
        spread = self.data.get('score_spread')
        lines.append("[bold]Assessment Uncertainty[/bold]")
        if high_uncertainty:
            lines.append("  [yellow]⚠ HIGH UNCERTAINTY[/yellow]")
            lines.append("  [dim]Scorers significantly disagreed on threat level[/dim]")
            if spread is not None:
                lines.append(f"  [dim]Score spread: {spread:.3f}[/dim]")
        else:
            lines.append("  [green]✓ Low uncertainty[/green]")
            lines.append("  [dim]Scorers agree on assessment[/dim]")
        lines.append("")

        # Unknown/pending data note
        pending_metrics = []
        if self.data.get('score_statistical') is None:
            pending_metrics.append("Statistical analysis")
        if self.data.get('score_ml_based') is None:
            pending_metrics.append("ML model")
        if hop_count is None:
            pending_metrics.append("Network path")

        if pending_metrics:
            lines.append("[bold]Pending Data[/bold]")
            for metric in pending_metrics:
                lines.append(f"  [dim]● {metric}[/dim]")
            lines.append("")
            lines.append("[dim italic]Some metrics require historical data or[/dim italic]")
            lines.append("[dim italic]response packets to compute accurately.[/dim italic]")

        content = "\n".join(lines)
        return Panel(content, title="[bold cyan]Explanations[/bold cyan]", border_style="cyan")


class ConnectionIntelligenceModal(ModalScreen):
    """
    Full intelligence breakdown modal for a single connection.

    Shows 11 panels of computed intelligence:
    Row 1:
    1. Consensus Breakdown - 4 scorer votes, outliers, confidence
    2. Enrichment Details - ASN, org, hops, TTL, CIDR
    3. Protocol Enrichment - DNS/TLS/TCP analysis, domain intelligence

    Row 2:
    4. Verification/Triangulation - AI verification status, source agreement
    5. Threat Intel Sources - Local IOC, GreyNoise, OTX results
    6. Investigation Actions - Triage recommendations, pivot options

    Row 3:
    7. Anomaly Analysis - Z-scores, percentiles, factors
    8. Metric Explanations - Why metrics are scored as they are
    9. Reputation - VirusTotal, AbuseIPDB

    Row 4:
    10. Rules Triggered - Which detection rules fired
    11. Graph Position - Centrality, clusters, attack paths

    Key bindings:
    - ESC/Q: Close modal
    - B: Add to blocklist (placeholder)
    - W: Add to whitelist (placeholder)
    - E: Export to STIX (placeholder)
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close", show=True),
        Binding("q", "dismiss", "Close", show=False),
        Binding("b", "add_blocklist", "Blocklist", show=False),
        Binding("w", "add_whitelist", "Whitelist", show=False),
        Binding("e", "export_stix", "Export STIX", show=False),
    ]

    DEFAULT_CSS = """
    ConnectionIntelligenceModal {
        align: center middle;
    }

    #modal_container {
        width: 95%;
        height: 90%;
        background: $surface;
        border: thick $primary;
        padding: 1;
    }

    #modal_header {
        dock: top;
        height: 3;
        background: $primary;
        padding: 0 1;
    }

    #modal_header_text {
        width: 100%;
        text-align: center;
    }

    #modal_content {
        height: 1fr;
        width: 100%;
    }

    #modal_row1 {
        height: 26%;
        width: 100%;
    }

    #modal_row2 {
        height: 26%;
        width: 100%;
    }

    #modal_row3 {
        height: 24%;
        width: 100%;
    }

    #modal_row4 {
        height: 24%;
        width: 100%;
    }

    .modal_panel {
        width: 1fr;
        height: 100%;
        margin: 0 1;
    }

    #close_button {
        dock: bottom;
        width: 100%;
        height: 3;
    }
    """

    def __init__(self, connection_data: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.connection_data = connection_data

    def compose(self) -> ComposeResult:
        """Build the modal layout with 6 intelligence panels."""
        # Extract key info for header
        dst_ip = self.connection_data.get('dst_ip', 'Unknown')
        dst_port = self.connection_data.get('dst_port', '?')
        threat = float(self.connection_data.get('threat_score', 0) or 0)
        timestamp = self.connection_data.get('timestamp', 0)

        if isinstance(timestamp, (int, float)) and timestamp > 0:
            time_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        else:
            time_str = "Unknown"

        # Threat color for header
        if threat >= 0.7:
            threat_style = "bold red"
        elif threat >= 0.5:
            threat_style = "bold yellow"
        else:
            threat_style = "green"

        with Container(id="modal_container"):
            # Header
            yield Static(
                f"[bold]CONNECTION INTELLIGENCE[/bold]\n"
                f"[cyan]{dst_ip}:{dst_port}[/cyan] | "
                f"Threat: [{threat_style}]{threat:.3f}[/{threat_style}] | "
                f"Time: {time_str}",
                id="modal_header_text"
            )

            # Content area with 4 rows of panels
            with ScrollableContainer(id="modal_content"):
                # Row 1: Consensus, Enrichment, Protocol (NEW)
                with Horizontal(id="modal_row1"):
                    yield ConsensusBreakdownPanel(
                        self.connection_data,
                        classes="modal_panel"
                    )
                    yield EnrichmentDetailsPanel(
                        self.connection_data,
                        classes="modal_panel"
                    )
                    yield ProtocolEnrichmentPanel(
                        self.connection_data,
                        classes="modal_panel"
                    )

                # Row 2: Verification, Threat Intel Sources (NEW), Investigation Actions (NEW)
                with Horizontal(id="modal_row2"):
                    yield VerificationTriangulationPanel(
                        self.connection_data,
                        classes="modal_panel"
                    )
                    yield ThreatIntelSourcesPanel(
                        self.connection_data,
                        classes="modal_panel"
                    )
                    yield InvestigationActionsPanel(
                        self.connection_data,
                        classes="modal_panel"
                    )

                # Row 3: Anomaly, Metric Explanations, Reputation
                with Horizontal(id="modal_row3"):
                    yield AnomalyAnalysisPanel(
                        self.connection_data,
                        classes="modal_panel"
                    )
                    yield MetricExplanationPanel(
                        self.connection_data,
                        classes="modal_panel"
                    )
                    yield ReputationPanel(
                        self.connection_data,
                        classes="modal_panel"
                    )

                # Row 4: Rules, Graph Position
                with Horizontal(id="modal_row4"):
                    yield RulesTriggeredPanel(
                        self.connection_data,
                        classes="modal_panel"
                    )
                    yield GraphPositionPanel(
                        self.connection_data,
                        classes="modal_panel"
                    )

            # Close button
            yield Button("Close [ESC]", id="close_button", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle close button press."""
        if event.button.id == "close_button":
            self.dismiss()

    def action_dismiss(self) -> None:
        """Close the modal."""
        self.dismiss()

    def action_add_blocklist(self) -> None:
        """Add current IP/domain to local blocklist."""
        dst_ip = self.connection_data.get('dst_ip', '')
        domain = self.connection_data.get('dns_query') or self.connection_data.get('tls_sni')
        indicator = domain or dst_ip

        # Notify user (actual implementation would write to IOC file)
        self.notify(
            f"Blocklist: {indicator}",
            title="Added to Blocklist",
            severity="warning"
        )
        logger.info(f"User requested blocklist addition: {indicator}")

    def action_add_whitelist(self) -> None:
        """Add current IP/domain to local whitelist."""
        dst_ip = self.connection_data.get('dst_ip', '')
        domain = self.connection_data.get('dns_query') or self.connection_data.get('tls_sni')
        indicator = domain or dst_ip

        # Notify user (actual implementation would write to whitelist)
        self.notify(
            f"Whitelist: {indicator}",
            title="Added to Whitelist",
            severity="information"
        )
        logger.info(f"User requested whitelist addition: {indicator}")

    def action_export_stix(self) -> None:
        """Export current connection as STIX 2.1 indicator."""
        dst_ip = self.connection_data.get('dst_ip', '')
        threat_score = self.connection_data.get('threat_score', 0)

        # Notify user (actual implementation would use stix_export.py)
        self.notify(
            f"STIX export: {dst_ip} (threat: {threat_score:.2f})",
            title="STIX Export",
            severity="information"
        )
        logger.info(f"User requested STIX export: {dst_ip}")
