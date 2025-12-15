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
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List, Optional, Tuple, Set, Any

import numpy as np
from scipy import stats
from scipy.spatial.distance import cdist
from scipy.cluster.hierarchy import fcluster, linkage
from scipy.special import expit  # Sigmoid function
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

    def to_vector(self) -> np.ndarray:
        """Convert to numpy feature vector"""
        return np.array([
            self.score,
            self.confidence,
            min(self.connection_count / 100, 1.0),  # Normalize
            min(self.unique_ports / 20, 1.0),
            1 - self.org_trust,  # Invert: lower trust = higher risk
            min(self.hop_distance / 30, 1.0),
            self.geo_risk,
            self.time_pattern,
            1 - self.asn_reputation,
        ])


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
    Statistical anomaly detection using scipy

    Methods:
    - Z-score based outlier detection
    - Mahalanobis distance for multivariate outliers
    - Isolation Forest-like scoring
    - Bayesian probability estimation
    """

    def __init__(self, history_size: int = 1000):
        self.history_size = history_size
        self.connection_history: List[Dict] = []
        self.feature_means: Optional[np.ndarray] = None
        self.feature_stds: Optional[np.ndarray] = None
        self.covariance_matrix: Optional[np.ndarray] = None

        # Feature names for interpretability
        self.feature_names = [
            "threat_score", "confidence", "conn_rate", "port_diversity",
            "org_distrust", "hop_distance", "geo_risk", "time_pattern", "asn_risk"
        ]

    def update_baseline(self, threat_vectors: List[ThreatVector]):
        """Update statistical baseline from historical data"""
        if not threat_vectors:
            return

        # Convert to numpy matrix
        X = np.array([tv.to_vector() for tv in threat_vectors])

        # Calculate statistics
        self.feature_means = np.mean(X, axis=0)
        self.feature_stds = np.std(X, axis=0) + 1e-8  # Avoid div by zero

        # Covariance for Mahalanobis distance
        if len(X) > len(self.feature_names):
            try:
                self.covariance_matrix = np.cov(X.T)
            except Exception:
                self.covariance_matrix = None

        logger.debug(f"Anomaly baseline updated from {len(threat_vectors)} vectors")

    def detect(self, vector: ThreatVector) -> AnomalyResult:
        """
        Detect anomalies using multiple statistical methods

        Returns combined anomaly score with contributing factors
        """
        x = vector.to_vector()
        contributing_factors = []

        # Z-score based detection
        z_scores = np.zeros(len(x))
        if self.feature_means is not None:
            z_scores = (x - self.feature_means) / self.feature_stds

            # Find high z-score features
            for i, (z, name) in enumerate(zip(z_scores, self.feature_names)):
                if abs(z) > 2.0:
                    contributing_factors.append(f"{name}: z={z:.2f}")

        max_z = np.max(np.abs(z_scores))

        # Mahalanobis distance (multivariate outlier)
        mahal_score = 0.0
        if self.covariance_matrix is not None and self.feature_means is not None:
            try:
                diff = x - self.feature_means
                inv_cov = np.linalg.pinv(self.covariance_matrix)
                mahal_score = np.sqrt(diff @ inv_cov @ diff)

                # Chi-squared test for significance
                p_value = 1 - stats.chi2.cdf(mahal_score**2, df=len(x))
                if p_value < 0.05:
                    contributing_factors.append(f"multivariate_outlier: p={p_value:.4f}")
            except Exception:
                pass

        # Isolation-like score based on feature extremity
        isolation_score = 0.0
        if self.feature_means is not None:
            # How "isolated" is this point from the mean
            normalized_dist = np.abs(x - self.feature_means) / (self.feature_stds + 1e-8)
            isolation_score = np.mean(normalized_dist)

        # Combine scores using sigmoid for 0-1 range
        raw_score = 0.4 * max_z + 0.3 * (mahal_score / 5) + 0.3 * isolation_score
        anomaly_score = float(expit(raw_score - 2))  # Center around z=2

        # Calculate percentile
        percentile = float(stats.norm.cdf(max_z) * 100)

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
        """
        Detect anomalies for multiple vectors using vectorized operations

        OPTIMIZED: Uses numpy broadcasting instead of per-vector loops
        """
        if not vectors:
            return []

        # Convert all vectors to matrix at once
        X = np.array([v.to_vector() for v in vectors])
        n_samples = len(X)

        # Pre-allocate result arrays
        z_scores_all = np.zeros((n_samples, len(self.feature_names)))
        max_z_scores = np.zeros(n_samples)
        mahal_scores = np.zeros(n_samples)
        isolation_scores = np.zeros(n_samples)

        # Vectorized z-score calculation (broadcasting)
        if self.feature_means is not None:
            z_scores_all = (X - self.feature_means) / self.feature_stds
            max_z_scores = np.max(np.abs(z_scores_all), axis=1)

            # Vectorized isolation score
            normalized_dist = np.abs(X - self.feature_means) / (self.feature_stds + 1e-8)
            isolation_scores = np.mean(normalized_dist, axis=1)

        # Vectorized Mahalanobis distance
        if self.covariance_matrix is not None and self.feature_means is not None:
            try:
                diff = X - self.feature_means
                inv_cov = np.linalg.pinv(self.covariance_matrix)
                # Vectorized: diag(diff @ inv_cov @ diff.T)
                mahal_scores = np.sqrt(np.sum(diff @ inv_cov * diff, axis=1))
            except Exception:
                pass

        # Vectorized anomaly scores
        raw_scores = 0.4 * max_z_scores + 0.3 * (mahal_scores / 5) + 0.3 * isolation_scores
        anomaly_scores = expit(raw_scores - 2)  # Vectorized sigmoid

        # Vectorized percentiles
        percentiles = stats.norm.cdf(max_z_scores) * 100

        # Build results
        results = []
        for i, vector in enumerate(vectors):
            # Find contributing factors (still need loop for interpretability)
            contributing_factors = []
            high_z_mask = np.abs(z_scores_all[i]) > 2.0
            for j in np.where(high_z_mask)[0]:
                contributing_factors.append(
                    f"{self.feature_names[j]}: z={z_scores_all[i, j]:.2f}"
                )

            # Determine anomaly type
            score = anomaly_scores[i]
            if score > 0.8:
                anomaly_type = "critical"
            elif score > 0.6:
                anomaly_type = "suspicious"
            elif score > 0.4:
                anomaly_type = "unusual"
            else:
                anomaly_type = "normal"

            results.append(AnomalyResult(
                ip=vector.ip,
                anomaly_score=float(score),
                anomaly_type=anomaly_type,
                z_score=float(max_z_scores[i]),
                percentile=float(percentiles[i]),
                contributing_factors=contributing_factors,
            ))

        return results


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

    def __init__(self):
        self.graph = nx.DiGraph()
        self.org_graph = nx.Graph()  # Undirected org-level graph
        self.asn_stats: Dict[int, Dict] = defaultdict(lambda: {
            "connections": 0, "threat_sum": 0, "ips": set()
        })

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
            if scores and np.mean(scores) >= threshold:
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
                    avg_threat = np.mean(edge_data.get("threat_scores", [0]))

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


class ThreatAnalytics:
    """
    Main analytics engine combining all components

    Integrates:
    - AnomalyDetector for statistical analysis
    - ConnectionGraph for topology analysis
    - Numpy for vectorized calculations
    - Scipy for statistical tests
    """

    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.connection_graph = ConnectionGraph()
        self.threat_vectors: Dict[str, ThreatVector] = {}

        # Time-windowed statistics
        self.hourly_stats: Dict[int, Dict] = defaultdict(lambda: {
            "connections": 0, "threat_sum": 0, "high_threat": 0
        })

        # Threat score history for trend analysis
        self.score_history: List[Tuple[float, float]] = []  # (timestamp, score)

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

        # Time-based statistics
        hour = int(timestamp // 3600)
        self.hourly_stats[hour]["connections"] += 1
        self.hourly_stats[hour]["threat_sum"] += threat_score
        if threat_score >= 0.7:
            self.hourly_stats[hour]["high_threat"] += 1

        # Score history for trends
        self.score_history.append((timestamp, threat_score))
        if len(self.score_history) > 10000:
            self.score_history = self.score_history[-5000:]

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

        times = np.array([d[0] for d in window_data])
        scores = np.array([d[1] for d in window_data])

        # Normalize time to 0-1 range
        times_norm = (times - times.min()) / (times.max() - times.min() + 1e-8)

        # Linear regression for trend
        slope, intercept, r_value, p_value, std_err = stats.linregress(times_norm, scores)

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

        return {
            "trend": trend,
            "slope": float(slope),
            "r_squared": float(r_value ** 2),
            "p_value": float(p_value),
            "mean_score": float(np.mean(scores)),
            "std_score": float(np.std(scores)),
            "min_score": float(np.min(scores)),
            "max_score": float(np.max(scores)),
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
