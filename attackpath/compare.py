import json
import random
import sys
from pathlib import Path

from attackpath.ingest import parse_nmap_xml
from attackpath.graph import build_graph
from attackpath.scoring import SERVICE_RISK, DEFAULT_RISK
from attackpath.evaluate import (port_of, cvss_of, our_ranking, baseline_ranking,
                                 precision_at_k, first_hit, average_precision)


def type_baseline(g):
    """CVSS first, then the service-type impact from the rule table."""
    items = []
    for n, d in g.nodes(data=True):
        if d.get("kind") == "service":
            impact = SERVICE_RISK.get(d.get("name", "").lower(), DEFAULT_RISK)[1]
            items.append((cvss_of(d), impact, port_of(n)))
    items.sort(key=lambda x: (-x[0], -x[1], x[2]))
    return [p for _, _, p in items]


def metrics(ranked, truth):
    return (precision_at_k(ranked, truth, 5), precision_at_k(ranked, truth, 10),
            first_hit(ranked, truth), average_precision(ranked, truth))


def main(scan, truth_file, runs=1000):
    g = build_graph(parse_nmap_xml(scan))
    ports = [port_of(n) for n, d in g.nodes(data=True) if d.get("kind") == "service"]
    truth = set(json.loads(Path(truth_file).read_text())["ports"]) & set(ports)

    rp5 = rp10 = rap = 0.0
    for _ in range(runs):
        r = ports[:]
        random.shuffle(r)
        m = metrics(r, truth)
        rp5, rp10, rap = rp5 + m[0], rp10 + m[1], rap + m[3]

    rows = [("Random", (rp5 / runs, rp10 / runs, "-", rap / runs)),
            ("CVSS only", metrics(baseline_ranking(g), truth)),
            ("CVSS + service type", metrics(type_baseline(g), truth)),
            ("AttackPath", metrics(our_ranking(g), truth))]

    print(f"Scan: {scan}")
    print(f"Ground-truth services in scan: {len(truth)} of {len(ports)}\n")
    print(f"{'Method':<22}{'P@5':>6}{'P@10':>7}{'1st':>6}{'AP':>8}")
    for name, (p5, p10, fh, ap) in rows:
        print(f"{name:<22}{p5:>6.2f}{p10:>7.2f}{str(fh):>6}{ap:>8.3f}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
