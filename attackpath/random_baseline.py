import json
import random
import sys
from pathlib import Path

from attackpath.ingest import parse_nmap_xml
from attackpath.graph import build_graph
from attackpath.evaluate import port_of, precision_at_k, average_precision


def main(scan, truth_file, runs=1000):
    g = build_graph(parse_nmap_xml(scan))
    ports = [port_of(n) for n, d in g.nodes(data=True) if d.get("kind") == "service"]
    truth = set(json.loads(Path(truth_file).read_text())["ports"]) & set(ports)
    p5 = ap = 0.0
    for _ in range(runs):
        r = ports[:]
        random.shuffle(r)
        p5 += precision_at_k(r, truth, 5)
        ap += average_precision(r, truth)
    print(f"Random baseline ({runs} runs): P@5={p5 / runs:.2f}  AP={ap / runs:.3f}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
