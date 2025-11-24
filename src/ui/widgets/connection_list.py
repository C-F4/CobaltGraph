"""
Connection List Widget
Displays live connections with color-coded threat levels
"""

import curses
from datetime import datetime
from typing import Dict, List


class ConnectionListWidget:
    """
    Live connection list widget

    Displays:
    - Recent connections
    - Threat scores with color coding
    - Country and ISP
    - Scroll support
    """

    def __init__(self, y: int, x: int, height: int, width: int, colors: Dict):
        self.y = y
        self.x = x
        self.height = height
        self.width = width
        self.colors = colors

    def get_threat_color(self, score: float) -> int:
        """Get color based on threat score"""
        if score >= 0.7:
            return self.colors['critical']
        elif score >= 0.5:
            return self.colors['high']
        elif score >= 0.3:
            return self.colors['medium']
        else:
            return self.colors['low']

    def get_threat_label(self, score: float) -> str:
        """Get threat level label"""
        if score >= 0.7:
            return "[CRIT]"
        elif score >= 0.5:
            return "[HIGH]"
        elif score >= 0.3:
            return "[MED]"
        else:
            return "[LOW]"

    def render_bar(self, score: float, width: int = 10) -> str:
        """Render a progress bar for threat score"""
        filled = int(score * width)
        bar = "█" * filled + "░" * (width - filled)
        return bar

    def render(self, screen, connections: List[Dict], is_active: bool, scroll_offset: int):
        """Render the connection list"""
        try:
            # Draw border
            border_attr = self.colors['header'] if is_active else self.colors['info']

            # Top border
            screen.addstr(self.y, self.x, "┌" + "─" * (self.width - 2) + "┐", border_attr)

            # Title
            title = " LIVE CONNECTIONS "
            if is_active:
                title += "●"
            title_x = self.x + (self.width - len(title)) // 2
            screen.addstr(self.y, title_x, title, border_attr)

            # Side borders
            for row in range(1, self.height - 1):
                screen.addstr(self.y + row, self.x, "│", border_attr)
                screen.addstr(self.y + row, self.x + self.width - 1, "│", border_attr)

            # Bottom border
            screen.addstr(self.y + self.height - 1, self.x, "└" + "─" * (self.width - 2) + "┘", border_attr)

            # Render connections
            if not connections:
                # No connections message
                msg = "No connections yet..."
                msg_x = self.x + (self.width - len(msg)) // 2
                msg_y = self.y + self.height // 2
                screen.addstr(msg_y, msg_x, msg, self.colors['info'])
                return

            # Display connections (scrollable)
            display_height = self.height - 3  # Account for borders and padding
            start_idx = scroll_offset
            end_idx = min(start_idx + display_height, len(connections))

            row = self.y + 1
            for i in range(start_idx, end_idx):
                if row >= self.y + self.height - 1:
                    break

                conn = connections[i]
                threat_score = conn.get('threat_score', 0.0)
                dst_ip = conn.get('dst_ip', 'Unknown')
                dst_port = conn.get('dst_port', 0)
                country = conn.get('country', 'Unknown')[:2]  # Country code
                protocol = conn.get('protocol', 'TCP')

                # Format connection line
                color = self.get_threat_color(threat_score)
                label = self.get_threat_label(threat_score)
                bar = self.render_bar(threat_score, width=5)

                # Line format: "● 8.8.8.8:443      ███░░ 0.05 [LOW] US"
                conn_str = f"● {dst_ip:15s}:{dst_port:<5d} {bar} {threat_score:0.2f} {label} {country}"

                # Truncate if too long
                max_len = self.width - 4
                if len(conn_str) > max_len:
                    conn_str = conn_str[:max_len - 3] + "..."

                screen.addstr(row, self.x + 2, conn_str[:max_len], color)
                row += 1

            # Scroll indicator
            if len(connections) > display_height:
                scroll_percent = min(100, int((scroll_offset / len(connections)) * 100))
                scroll_info = f" {scroll_offset + 1}-{end_idx}/{len(connections)} ({scroll_percent}%) "
                screen.addstr(
                    self.y + self.height - 1,
                    self.x + self.width - len(scroll_info) - 2,
                    scroll_info,
                    self.colors['info']
                )

        except curses.error:
            # Ignore errors (terminal too small)
            pass
