import json
import sys
from pathlib import Path

from attackpath.ingest import parse_nmap_xml
from attackpath.graph import build_graph
from attackpath.ranker import rank_paths
from attackpath.scoring import CVE_MAP, CVSS_CACHE

DATA = Path(__file__).resolve().parent.parent / "data"


def port_of(service_node):
    return int(service_node.split(":")[1].split("/")[0])


def cvss_of(data):
    """Highest cached CVSS among CVEs matching the service banner (0 if none)."""
    banner = f"{data.get('product', '')} {data.get('version', '')}".lower()
    best = 0.0
    for keyword, cves in CVE_MAP.items():
        if keyword in banner:
            for cve in cves:
                best = max(best, CVSS_CACHE.get(cve, {}).get("cvss") or 0)
    return best


def our_ranking(g):
    return [port_of(r["path"][1]) for r in rank_paths(g, 1000)]


def baseline_ranking(g):
    """Plain CVSS order. Ties are broken by port number."""
    items = [(cvss_of(d), port_of(n)) for n, d in g.nodes(data=True)
             if d.get("kind") == "service"]
    items.sort(key=lambda x: (-x[0], x[1]))
    return [port for _, port in items]


def precision_at_k(ranked, truth, k):
    return sum(1 for p in ranked[:k] if p in truth) / k


def first_hit(ranked, truth):
    for i, p in enumerate(ranked, 1):
        if p in truth:
            return i
    return None


def average_precision(ranked, truth):
    hits, total = 0, 0.0
    for i, p in enumerate(ranked, 1):
        if p in truth:
            hits += 1
            total += hits / i
    return total / len(truth) if truth else 0.0


def evaluate(scan, truth_file):
    g = build_graph(parse_nmap_xml(scan))
    truth = set(json.loads(Path(truth_file).read_text())["ports"])
    truth &= {port_of(n) for n, d in g.nodes(data=True) if d.get("kind") == "service"}

    rows = {}
    for name, ranked in (("Baseline (CVSS only)", baseline_ranking(g)),
                         ("AttackPath", our_ranking(g))):
        rows[name] = {
            "P@5": round(precision_at_k(ranked, truth, 5), 2),
            "P@10": round(precision_at_k(ranked, truth, 10), 2),
            "first_hit_rank": first_hit(ranked, truth),
            "avg_precision": round(average_precision(ranked, truth), 3),
            "top10_ports": ranked[:10],
        }
    return rows, len(truth)


if __name__ == "__main__":
    scan = sys.argv[1]
    truth_file = sys.argv[2] if len(sys.argv) > 2 else DATA / "ground_truth.json"
    rows, n_truth = evaluate(scan, truth_file)
    print(f"Ground-truth services present in scan: {n_truth}\n")
    print(f"{'Method':<22}{'P@5':>6}{'P@10':>7}{'1st hit':>9}{'AP':>8}")
    for name, m in rows.items():
        print(f"{name:<22}{m['P@5']:>6}{m['P@10']:>7}{str(m['first_hit_rank']):>9}{m['avg_precision']:>8}")
    print()
    for name, m in rows.items():
        print(f"{name} top 10 ports: {m['top10_ports']}")
