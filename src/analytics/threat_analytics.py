#!/usr/bin/env python3
"""
Advanced Threat Analytics Engine - OPTIMIZED
High-performance scipy/numpy/networkx threat analysis

Performance optimizations:
- Fully vectorized anomaly detection (batch operations)
- Pre-computed feature matrices
- Cached statistical baselines
- Efficient numpy broadcasting

Features:
- Statistical anomaly detection using scipy
- Graph-based connection topology with networkx
- Vectorized threat calculations with numpy
- Bayesian threat probability estimation
"""

import logging
import time
import traceback
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List, Optional, Tuple, Set, Any

import math

try:
    import numpy as np
    from scipy import stats
    from scipy.spatial.distance import cdist
    from scipy.cluster.hierarchy import fcluster, linkage
    from scipy.special import expit  # Sigmoid function
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None
    stats = None

    def expit(x):
        """Pure Python sigmoid function"""
        if isinstance(x, (list, tuple)):
            return [1.0 / (1.0 + math.exp(-v)) for v in x]
        return 1.0 / (1.0 + math.exp(-min(max(x, -500), 500)))

import networkx as nx

logger = logging.getLogger(__name__)


@dataclass
class ThreatVector:
    """Multi-dimensional threat representation"""
    ip: str
    score: float                    # Consensus threat score
    confidence: float               # Scorer confidence
    connection_count: int           # Number of connections
    unique_ports: int               # Port diversity
    org_trust: float               # Organization trust score
    hop_distance: int              # Network hops
    geo_risk: float                # Geographic risk factor
    time_pattern: float            # Temporal pattern score
    asn_reputation: float          # ASN-based reputation

    def to_vector(self):
        """Convert to feature vector (numpy array if available, else list)"""
        values = [
            self.score,
            self.confidence,
            min(self.connection_count / 100, 1.0),  # Normalize
            min(self.unique_ports / 20, 1.0),
            1 - self.org_trust,  # Invert: lower trust = higher risk
            min(self.hop_distance / 30, 1.0),
            self.geo_risk,
            self.time_pattern,
            1 - self.asn_reputation,
        ]
        if HAS_NUMPY:
            return np.array(values)
        return values


@dataclass
class AnomalyResult:
    """Result of anomaly detection"""
    ip: str
    anomaly_score: float           # 0-1, higher = more anomalous
    anomaly_type: str              # Type of anomaly detected
    z_score: float                 # Statistical z-score
    percentile: float              # Percentile rank
    contributing_factors: List[str]
    timestamp: float = field(default_factory=time.time)


class AnomalyDetector:
    """
    Statistical anomaly detection using scipy (with pure Python fallback)

    Methods:
    - Z-score based outlier detection
    - Mahalanobis distance for multivariate outliers (numpy only)
    - Isolation Forest-like scoring
    - Bayesian probability estimation
    """

    def __init__(self, history_size: int = 1000):
        self.history_size = history_size
        self.connection_history: List[Dict] = []
        self.feature_means: Optional[List[float]] = None
        self.feature_stds: Optional[List[float]] = None
        self.covariance_matrix = None  # numpy-only feature

        # Feature names for interpretability
        self.feature_names = [
            "threat_score", "confidence", "conn_rate", "port_diversity",
            "org_distrust", "hop_distance", "geo_risk", "time_pattern", "asn_risk"
        ]

    @staticmethod
    def _mean(values):
        """Pure Python mean"""
        return sum(values) / len(values) if values else 0.0

    @staticmethod
    def _std(values):
        """Pure Python standard deviation"""
        if len(values) < 2:
            return 0.0
        m = sum(values) / len(values)
        return math.sqrt(sum((v - m) ** 2 for v in values) / len(values))

    @staticmethod
    def _norm_cdf(z):
        """Pure Python approximation of normal CDF"""
        return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))

    def update_baseline(self, threat_vectors: List[ThreatVector]):
        """Update statistical baseline from historical data"""
        if not threat_vectors:
            return

        vectors = [tv.to_vector() for tv in threat_vectors]
        n_features = len(self.feature_names)

        if HAS_NUMPY:
            X = np.array(vectors)
            self.feature_means = np.mean(X, axis=0).tolist()
            self.feature_stds = (np.std(X, axis=0) + 1e-8).tolist()
            if len(X) > n_features:
                try:
                    self.covariance_matrix = np.cov(X.T)
                except Exception:
                    self.covariance_matrix = None
        else:
            # Pure Python column-wise statistics
            self.feature_means = []
            self.feature_stds = []
            for j in range(n_features):
                col = [v[j] for v in vectors]
                self.feature_means.append(self._mean(col))
                self.feature_stds.append(self._std(col) + 1e-8)
            self.covariance_matrix = None  # Skip Mahalanobis without numpy

        logger.debug(f"Anomaly baseline updated from {len(threat_vectors)} vectors")

    def detect(self, vector: ThreatVector) -> AnomalyResult:
        """
        Detect anomalies using multiple statistical methods

        Returns combined anomaly score with contributing factors
        """
        x = vector.to_vector()
        contributing_factors = []
        n = len(x)

        # Z-score based detection
        z_scores = [0.0] * n
        if self.feature_means is not None:
            z_scores = [(x[i] - self.feature_means[i]) / self.feature_stds[i] for i in range(n)]

            for i, (z, name) in enumerate(zip(z_scores, self.feature_names)):
                if abs(z) > 2.0:
                    contributing_factors.append(f"{name}: z={z:.2f}")

        max_z = max(abs(z) for z in z_scores) if z_scores else 0.0

        # Mahalanobis distance (numpy-only)
        mahal_score = 0.0
        if HAS_NUMPY and self.covariance_matrix is not None and self.feature_means is not None:
            try:
                x_np = np.array(x)
                means_np = np.array(self.feature_means)
                diff = x_np - means_np
                inv_cov = np.linalg.pinv(self.covariance_matrix)
                mahal_score = float(np.sqrt(diff @ inv_cov @ diff))

                p_value = 1 - stats.chi2.cdf(mahal_score**2, df=n)
                if p_value < 0.05:
                    contributing_factors.append(f"multivariate_outlier: p={p_value:.4f}")
            except Exception:
                pass

        # Isolation-like score based on feature extremity
        isolation_score = 0.0
        if self.feature_means is not None:
            normalized_dist = [abs(x[i] - self.feature_means[i]) / (self.feature_stds[i] + 1e-8)
                               for i in range(n)]
            isolation_score = self._mean(normalized_dist)

        # Combine scores using sigmoid for 0-1 range
        raw_score = 0.4 * max_z + 0.3 * (mahal_score / 5) + 0.3 * isolation_score
        anomaly_score = float(expit(raw_score - 2))

        # Calculate percentile
        percentile = self._norm_cdf(max_z) * 100

        # Determine anomaly type
        anomaly_type = "normal"
        if anomaly_score > 0.8:
            anomaly_type = "critical"
        elif anomaly_score > 0.6:
            anomaly_type = "suspicious"
        elif anomaly_score > 0.4:
            anomaly_type = "unusual"

        return AnomalyResult(
            ip=vector.ip,
            anomaly_score=anomaly_score,
            anomaly_type=anomaly_type,
            z_score=float(max_z),
            percentile=percentile,
            contributing_factors=contributing_factors,
        )

    def batch_detect(self, vectors: List[ThreatVector]) -> List[AnomalyResult]:
        """Detect anomalies for multiple vectors"""
        return [self.detect(v) for v in vectors]


class ConnectionGraph:
    """
    Network topology analysis using networkx

    Models connections as a directed graph:
    - Nodes: IP addresses (with attributes)
    - Edges: Connections (with threat scores, ports, timestamps)

    Provides:
    - Centrality analysis (hub detection)
    - Community detection (threat clusters)
    - Path analysis (attack chains)
    - Temporal patterns
    """

    def __init__(self, max_nodes: int = 3000, max_asns: int = 500):
        self.graph = nx.DiGraph()
        self.org_graph = nx.Graph()  # Undirected org-level graph
        self.asn_stats: Dict[int, Dict] = defaultdict(lambda: {
            "connections": 0, "threat_sum": 0, "ips": set()
        })
        self._max_nodes = max_nodes
        self._max_asns = max_asns
        self._prune_counter = 0

    def add_connection(
        self,
        src_ip: str,
        dst_ip: str,
        threat_score: float,
        dst_port: int,
        dst_asn: Optional[int] = None,
        dst_org: Optional[str] = None,
        dst_org_type: Optional[str] = None,
        hop_count: Optional[int] = None,
        timestamp: Optional[float] = None,
    ):
        """Add a connection to the graph"""
        timestamp = timestamp or time.time()

        # Add/update source node
        if not self.graph.has_node(src_ip):
            self.graph.add_node(src_ip, type="source", first_seen=timestamp)

        # Add/update destination node
        if not self.graph.has_node(dst_ip):
            self.graph.add_node(
                dst_ip,
                type="destination",
                asn=dst_asn,
                org=dst_org,
                org_type=dst_org_type,
                first_seen=timestamp,
                threat_scores=[],
            )

        # Update node attributes
        node_data = self.graph.nodes[dst_ip]
        if "threat_scores" not in node_data:
            node_data["threat_scores"] = []
        node_data["threat_scores"].append(threat_score)
        node_data["last_seen"] = timestamp

        # Add/update edge
        edge_key = (src_ip, dst_ip)
        if self.graph.has_edge(src_ip, dst_ip):
            edge_data = self.graph.edges[edge_key]
            edge_data["count"] = edge_data.get("count", 0) + 1
            edge_data["ports"].add(dst_port)
            edge_data["threat_scores"].append(threat_score)
            edge_data["last_seen"] = timestamp
        else:
            self.graph.add_edge(
                src_ip, dst_ip,
                count=1,
                ports={dst_port},
                threat_scores=[threat_score],
                first_seen=timestamp,
                last_seen=timestamp,
                hop_count=hop_count,
            )

        # Update ASN statistics
        if dst_asn:
            self.asn_stats[dst_asn]["connections"] += 1
            self.asn_stats[dst_asn]["threat_sum"] += threat_score
            self.asn_stats[dst_asn]["ips"].add(dst_ip)

        # Organization-level graph
        if dst_org:
            if not self.org_graph.has_node(dst_org):
                self.org_graph.add_node(dst_org, org_type=dst_org_type, asn=dst_asn)
            if not self.org_graph.has_edge("local", dst_org):
                self.org_graph.add_edge("local", dst_org, weight=0)
            self.org_graph.edges["local", dst_org]["weight"] += 1

        # Periodic pruning to bound memory
        self._prune_counter += 1
        if self._prune_counter >= 100:
            self._prune_counter = 0
            self._prune_if_needed()

    def get_high_centrality_nodes(self, top_n: int = 10) -> List[Tuple[str, float]]:
        """
        Find nodes with highest centrality (potential C2 servers or hubs)

        Uses PageRank for directed graphs
        """
        if len(self.graph) == 0:
            return []

        try:
            pagerank = nx.pagerank(self.graph, alpha=0.85)
            sorted_nodes = sorted(pagerank.items(), key=lambda x: x[1], reverse=True)
            return sorted_nodes[:top_n]
        except Exception as e:
            logger.warning(f"PageRank calculation failed: {e}")
            return []

    def get_threat_clusters(self, threshold: float = 0.7) -> List[Set[str]]:
        """
        Identify clusters of high-threat destinations

        Uses connected components on subgraph of high-threat nodes
        """
        # Filter to high-threat nodes
        high_threat_nodes = []
        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            scores = node_data.get("threat_scores", [])
            if scores and (sum(scores) / len(scores)) >= threshold:
                high_threat_nodes.append(node)

        if not high_threat_nodes:
            return []

        # Create subgraph and find connected components
        subgraph = self.graph.subgraph(high_threat_nodes).to_undirected()
        clusters = list(nx.connected_components(subgraph))

        return [c for c in clusters if len(c) > 1]

    def get_attack_paths(self, min_threat: float = 0.6) -> List[List[str]]:
        """
        Find potential attack chains (paths of high-threat connections)
        """
        paths = []

        # Find source nodes (nodes with no incoming edges from high-threat)
        sources = [n for n in self.graph.nodes()
                   if self.graph.in_degree(n) == 0 or
                   self.graph.nodes[n].get("type") == "source"]

        for source in sources:
            # DFS to find paths with consistently high threat
            visited = set()
            stack = [(source, [source])]

            while stack:
                node, path = stack.pop()
                if node in visited:
                    continue
                visited.add(node)

                for successor in self.graph.successors(node):
                    edge_data = self.graph.edges[node, successor]
                    _scores = edge_data.get("threat_scores", [0])
                    avg_threat = sum(_scores) / len(_scores) if _scores else 0

                    if avg_threat >= min_threat:
                        new_path = path + [successor]
                        if len(new_path) >= 2:
                            paths.append(new_path)
                        stack.append((successor, new_path))

        return paths

    def get_asn_threat_ranking(self) -> List[Tuple[int, float, int]]:
        """
        Rank ASNs by average threat score

        Returns: List of (asn, avg_threat, connection_count)
        """
        rankings = []
        for asn, stats in self.asn_stats.items():
            if stats["connections"] > 0:
                avg_threat = stats["threat_sum"] / stats["connections"]
                rankings.append((asn, avg_threat, stats["connections"]))

        return sorted(rankings, key=lambda x: x[1], reverse=True)

    def get_org_type_distribution(self) -> Dict[str, Dict]:
        """Get connection distribution by organization type"""
        dist = defaultdict(lambda: {"count": 0, "threat_sum": 0, "ips": set()})

        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            org_type = node_data.get("org_type", "unknown")
            scores = node_data.get("threat_scores", [])

            if scores:
                dist[org_type]["count"] += len(scores)
                dist[org_type]["threat_sum"] += sum(scores)
                dist[org_type]["ips"].add(node)

        # Calculate averages
        result = {}
        for org_type, data in dist.items():
            result[org_type] = {
                "connection_count": data["count"],
                "unique_ips": len(data["ips"]),
                "avg_threat": data["threat_sum"] / max(data["count"], 1),
            }

        return result

    def get_graph_metrics(self) -> Dict:
        """Get overall graph metrics"""
        if len(self.graph) == 0:
            return {
                "nodes": 0,
                "edges": 0,
                "density": 0.0,
                "avg_degree": 0.0,
                "unique_asns": 0,
                "unique_orgs": 0,
            }

        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "density": nx.density(self.graph),
            "avg_degree": sum(dict(self.graph.degree()).values()) / max(len(self.graph), 1),
            "unique_asns": len(self.asn_stats),
            "unique_orgs": max(0, self.org_graph.number_of_nodes() - 1),  # Exclude "local"
        }

    def _prune_if_needed(self):
        """
        Prune old/low-activity nodes to bound memory usage

        Removes nodes that:
        - Have oldest last_seen timestamps
        - Have lowest threat scores
        """
        import time
        now = time.time()

        # Prune main graph if too large
        if self.graph.number_of_nodes() > self._max_nodes:
            # Get node scores: weighted by recency and threat
            node_scores = []
            for node in self.graph.nodes():
                data = self.graph.nodes[node]
                last_seen = data.get("last_seen", 0)
                threat_scores = data.get("threat_scores", [0])
                avg_threat = (sum(threat_scores) / len(threat_scores)) if threat_scores else 0
                # Score: recency (0-1) + threat (0-1)
                recency = max(0, 1 - (now - last_seen) / 3600)  # 1 hour window
                node_scores.append((node, recency + avg_threat))

            # Sort by score, remove lowest 20%
            node_scores.sort(key=lambda x: x[1])
            remove_count = len(node_scores) // 5
            for node, _ in node_scores[:remove_count]:
                if node != "local":  # Keep local node
                    self.graph.remove_node(node)

        # Prune ASN stats if too large
        if len(self.asn_stats) > self._max_asns:
            # Keep ASNs with most connections
            sorted_asns = sorted(
                self.asn_stats.items(),
                key=lambda x: x[1]["connections"],
                reverse=True
            )
            keep = dict(sorted_asns[:self._max_asns * 4 // 5])
            self.asn_stats = defaultdict(lambda: {
                "connections": 0, "threat_sum": 0, "ips": set()
            }, keep)

        # Prune org graph if too large
        if self.org_graph.number_of_nodes() > self._max_nodes // 2:
            # Remove low-weight edges and isolated nodes
            edges_to_remove = [
                (u, v) for u, v, d in self.org_graph.edges(data=True)
                if d.get("weight", 0) < 3
            ]
            self.org_graph.remove_edges_from(edges_to_remove)
            # Remove isolated nodes (except "local")
            isolated = [n for n in nx.isolates(self.org_graph) if n != "local"]
            self.org_graph.remove_nodes_from(isolated)


class ThreatAnalytics:
    """
    Main analytics engine combining all components

    Integrates:
    - AnomalyDetector for statistical analysis
    - ConnectionGraph for topology analysis
    - Numpy for vectorized calculations
    - Scipy for statistical tests
    """

    def __init__(self, max_threat_vectors: int = 5000, max_hourly_buckets: int = 168):
        self.anomaly_detector = AnomalyDetector()
        self.connection_graph = ConnectionGraph()
        self.threat_vectors: Dict[str, ThreatVector] = {}
        self._max_threat_vectors = max_threat_vectors  # ~5000 unique IPs

        # Time-windowed statistics (168 hours = 1 week max)
        self.hourly_stats: Dict[int, Dict] = defaultdict(lambda: {
            "connections": 0, "threat_sum": 0, "high_threat": 0
        })
        self._max_hourly_buckets = max_hourly_buckets

        # Threat score history for trend analysis (bounded deque for memory efficiency)
        self.score_history: deque = deque(maxlen=5000)  # (timestamp, score)

    def process_connection(
        self,
        src_ip: str,
        dst_ip: str,
        threat_score: float,
        confidence: float,
        dst_port: int,
        dst_asn: Optional[int] = None,
        dst_org: Optional[str] = None,
        dst_org_type: Optional[str] = None,
        org_trust: float = 0.5,
        hop_count: int = 0,
        geo_risk: float = 0.5,
        timestamp: Optional[float] = None,
        dst_country: Optional[str] = None,
        org_trust_score: Optional[float] = None,
    ) -> Dict:
        """
        Process a new connection through the analytics pipeline

        Returns comprehensive analysis including:
        - Anomaly detection results
        - Graph-based insights
        - Trend analysis
        """
        timestamp = timestamp or time.time()

        # Use org_trust_score if provided, otherwise fall back to org_trust
        effective_org_trust = org_trust_score if org_trust_score is not None else org_trust

        # Add to graph
        self.connection_graph.add_connection(
            src_ip=src_ip,
            dst_ip=dst_ip,
            threat_score=threat_score,
            dst_port=dst_port,
            dst_asn=dst_asn,
            dst_org=dst_org,
            dst_org_type=dst_org_type,
            hop_count=hop_count,
            timestamp=timestamp,
        )

        # Update/create threat vector
        if dst_ip in self.threat_vectors:
            tv = self.threat_vectors[dst_ip]
            tv.score = (tv.score + threat_score) / 2  # Running average
            tv.connection_count += 1
        else:
            tv = ThreatVector(
                ip=dst_ip,
                score=threat_score,
                confidence=confidence,
                connection_count=1,
                unique_ports=1,
                org_trust=effective_org_trust,
                hop_distance=hop_count,
                geo_risk=geo_risk,
                time_pattern=0.5,
                asn_reputation=effective_org_trust,
            )
            self.threat_vectors[dst_ip] = tv

        # Update port diversity
        node_data = self.connection_graph.graph.nodes.get(dst_ip, {})
        if dst_ip in self.connection_graph.graph:
            ports = set()
            for _, _, edge_data in self.connection_graph.graph.in_edges(dst_ip, data=True):
                ports.update(edge_data.get("ports", set()))
            tv.unique_ports = len(ports)

        # Anomaly detection
        anomaly = None
        if len(self.threat_vectors) > 10:
            # Update baseline periodically
            if len(self.threat_vectors) % 50 == 0:
                self.anomaly_detector.update_baseline(list(self.threat_vectors.values()))
            anomaly = self.anomaly_detector.detect(tv)

        # Time-based statistics with memory bounds
        hour = int(timestamp // 3600)
        self.hourly_stats[hour]["connections"] += 1
        self.hourly_stats[hour]["threat_sum"] += threat_score
        if threat_score >= 0.7:
            self.hourly_stats[hour]["high_threat"] += 1

        # Prune old hourly buckets (keep last week)
        if len(self.hourly_stats) > self._max_hourly_buckets:
            oldest = min(self.hourly_stats.keys())
            del self.hourly_stats[oldest]

        # Bound threat_vectors dict
        if len(self.threat_vectors) > self._max_threat_vectors:
            # Remove lowest-scored 20%
            sorted_vectors = sorted(
                self.threat_vectors.items(),
                key=lambda x: x[1].score,
                reverse=True
            )
            self.threat_vectors = dict(sorted_vectors[:self._max_threat_vectors * 4 // 5])

        # Score history for trends (deque auto-evicts oldest)
        self.score_history.append((timestamp, threat_score))

        # Build result
        result = {
            "dst_ip": dst_ip,
            "threat_score": threat_score,
            "confidence": confidence,
            "connection_count": tv.connection_count,
            "port_diversity": tv.unique_ports,
        }

        if anomaly:
            result["anomaly"] = {
                "score": anomaly.anomaly_score,
                "type": anomaly.anomaly_type,
                "z_score": anomaly.z_score,
                "factors": anomaly.contributing_factors,
            }

        return result

    @staticmethod
    def _linregress(x, y):
        """Pure Python simple linear regression returning (slope, intercept, r, p_value)"""
        n = len(x)
        if n < 2:
            return 0.0, 0.0, 0.0, 1.0
        sx = sum(x)
        sy = sum(y)
        sxx = sum(xi * xi for xi in x)
        sxy = sum(xi * yi for xi, yi in zip(x, y))
        syy = sum(yi * yi for yi in y)
        denom = n * sxx - sx * sx
        if abs(denom) < 1e-12:
            return 0.0, sy / n, 0.0, 1.0
        slope = (n * sxy - sx * sy) / denom
        intercept = (sy - slope * sx) / n
        # Correlation coefficient
        denom_r = math.sqrt((n * sxx - sx ** 2) * (n * syy - sy ** 2))
        r = (n * sxy - sx * sy) / denom_r if abs(denom_r) > 1e-12 else 0.0
        # Approximate p-value via t-distribution
        if abs(r) >= 1.0 - 1e-12:
            p_value = 0.0
        elif n > 2:
            t_stat = r * math.sqrt((n - 2) / (1 - r * r + 1e-12))
            # Approximate two-tailed p-value using normal CDF for large n
            p_value = 2.0 * (1.0 - 0.5 * (1.0 + math.erf(abs(t_stat) / math.sqrt(2.0))))
        else:
            p_value = 1.0
        return slope, intercept, r, p_value

    def get_threat_trend(self, window_hours: int = 24) -> Dict:
        """
        Analyze threat score trends over time

        Uses scipy for statistical trend analysis
        """
        if len(self.score_history) < 10:
            return {"trend": "insufficient_data"}

        now = time.time()
        window_start = now - (window_hours * 3600)

        # Filter to window
        window_data = [(t, s) for t, s in self.score_history if t >= window_start]

        if len(window_data) < 10:
            return {"trend": "insufficient_data"}

        times_raw = [d[0] for d in window_data]
        scores_raw = [d[1] for d in window_data]

        t_min, t_max = min(times_raw), max(times_raw)
        t_range = t_max - t_min + 1e-8
        times_norm = [(t - t_min) / t_range for t in times_raw]

        # Linear regression (pure Python)
        slope, intercept, r_value, p_value = self._linregress(times_norm, scores_raw)

        # Determine trend direction
        if p_value < 0.05:
            if slope > 0.1:
                trend = "increasing"
            elif slope < -0.1:
                trend = "decreasing"
            else:
                trend = "stable"
        else:
            trend = "stable"

        mean_s = sum(scores_raw) / len(scores_raw)
        std_s = math.sqrt(sum((s - mean_s) ** 2 for s in scores_raw) / len(scores_raw)) if len(scores_raw) > 1 else 0.0

        return {
            "trend": trend,
            "slope": float(slope),
            "r_squared": float(r_value ** 2),
            "p_value": float(p_value),
            "mean_score": mean_s,
            "std_score": std_s,
            "min_score": min(scores_raw),
            "max_score": max(scores_raw),
            "sample_count": len(window_data),
        }

    def get_geographic_risk_map(self) -> Dict[str, float]:
        """
        Calculate risk scores by geographic region

        Aggregates threat scores by country/region
        """
        # This would integrate with geo_lookup data
        # For now, aggregate by org_type as proxy
        org_dist = self.connection_graph.get_org_type_distribution()

        risk_map = {}
        for org_type, data in org_dist.items():
            risk_map[org_type] = data["avg_threat"]

        return risk_map

    def get_comprehensive_report(self) -> Dict:
        """
        Generate comprehensive threat intelligence report
        """
        graph_metrics = self.connection_graph.get_graph_metrics()

        # High centrality nodes (potential C2)
        central_nodes = self.connection_graph.get_high_centrality_nodes(5)

        # Threat clusters
        clusters = self.connection_graph.get_threat_clusters()

        # ASN rankings
        asn_ranking = self.connection_graph.get_asn_threat_ranking()[:10]

        # Org type distribution
        org_distribution = self.connection_graph.get_org_type_distribution()

        # Trend analysis
        trend = self.get_threat_trend()

        # Attack paths
        attack_paths = self.connection_graph.get_attack_paths()[:5]

        return {
            "summary": {
                "total_connections": graph_metrics["edges"],
                "unique_destinations": graph_metrics["nodes"],
                "unique_asns": graph_metrics["unique_asns"],
                "unique_orgs": graph_metrics["unique_orgs"],
                "graph_density": graph_metrics["density"],
            },
            "threat_trend": trend,
            "high_centrality_ips": [
                {"ip": ip, "centrality": score}
                for ip, score in central_nodes
            ],
            "threat_clusters": [
                {"size": len(c), "ips": list(c)[:5]}
                for c in clusters
            ],
            "top_threat_asns": [
                {"asn": asn, "avg_threat": avg, "connections": count}
                for asn, avg, count in asn_ranking
            ],
            "org_type_risk": org_distribution,
            "potential_attack_paths": attack_paths,
            "generated_at": time.time(),
        }


# Convenience function for quick analysis
def analyze_connection(
    src_ip: str,
    dst_ip: str,
    threat_score: float,
    **kwargs
) -> Dict:
    """Quick single-connection analysis"""
    analytics = ThreatAnalytics()
    return analytics.process_connection(
        src_ip=src_ip,
        dst_ip=dst_ip,
        threat_score=threat_score,
        confidence=kwargs.get("confidence", 0.8),
        dst_port=kwargs.get("dst_port", 443),
        **kwargs
    )


if __name__ == "__main__":
    # Test the analytics engine
    logging.basicConfig(level=logging.INFO)

    analytics = ThreatAnalytics()

    # Simulate connections
    test_connections = [
        ("192.168.1.1", "8.8.8.8", 0.1, 53, 15169, "Google", "cloud"),
        ("192.168.1.1", "1.1.1.1", 0.15, 53, 13335, "Cloudflare", "cdn"),
        ("192.168.1.1", "104.16.132.229", 0.2, 443, 13335, "Cloudflare", "cdn"),
        ("192.168.1.1", "185.220.101.1", 0.85, 443, 0, "Tor Exit", "tor_proxy"),
        ("192.168.1.1", "185.220.101.2", 0.9, 443, 0, "Tor Exit", "tor_proxy"),
        ("192.168.1.1", "45.33.32.156", 0.75, 8080, 63949, "Linode", "hosting"),
    ]

    print("=" * 70)
    print("Threat Analytics Engine Test")
    print("=" * 70)

    for src, dst, score, port, asn, org, org_type in test_connections:
        result = analytics.process_connection(
            src_ip=src,
            dst_ip=dst,
            threat_score=score,
            confidence=0.8,
            dst_port=port,
            dst_asn=asn,
            dst_org=org,
            dst_org_type=org_type,
        )
        print(f"\n{dst}: score={score:.2f}, anomaly={result.get('anomaly', {}).get('type', 'N/A')}")

    print("\n" + "=" * 70)
    print("Comprehensive Report")
    print("=" * 70)

    report = analytics.get_comprehensive_report()
    print(f"\nSummary: {report['summary']}")
    print(f"Trend: {report['threat_trend']}")
    print(f"High Centrality: {report['high_centrality_ips']}")
    print(f"Org Risk: {report['org_type_risk']}")
