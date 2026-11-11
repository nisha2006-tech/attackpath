import sys
from attackpath.ingest import parse_nmap_xml
from attackpath.graph import build_graph, paths_to_hosts
from attackpath.scoring import score_node


def rank_paths(g, top_n=10):
    ranked = []
    for host, paths in paths_to_hosts(g).items():
        for p in paths:
            likelihood, impact, reasons = 1.0, 0, []
            for node in p:
                data = g.nodes[node]
                if data.get("kind") == "service":
                    s = score_node(data)
                    likelihood *= s["likelihood"]
                    impact = s["impact"]
                    reasons += s["reasons"]
            if impact == 0:
                continue
            ranked.append({
                "path": p,
                "likelihood": round(likelihood, 3),
                "impact": impact,
                "score": round(likelihood * impact, 2),
                "reasons": reasons,
            })
    ranked.sort(key=lambda r: r["score"], reverse=True)
    return ranked[:top_n]


if __name__ == "__main__":
    g = build_graph(parse_nmap_xml(sys.argv[1]))
    for i, r in enumerate(rank_paths(g, 10), 1):
        print(f"#{i}  score={r['score']}  (likelihood {r['likelihood']}, impact {r['impact']})")
        print("    " + " -> ".join(r["path"]))
        print("    why: " + "; ".join(r["reasons"]))
