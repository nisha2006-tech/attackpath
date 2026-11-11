import sys
import networkx as nx
from attackpath.ingest import parse_nmap_xml

ATTACKER = "attacker"


def service_id(host, svc):
    return f"{host.ip}:{svc.port}/{svc.protocol}"


def build_graph(hosts):
    """Build a directed attack graph from parsed hosts."""
    g = nx.DiGraph()
    g.add_node(ATTACKER, kind="attacker")

    for h in hosts:
        g.add_node(h.ip, kind="host", hostname=h.hostname)
        for s in h.services:
            sid = service_id(h, s)
            g.add_node(sid, kind="service", host=h.ip, port=s.port,
                       name=s.name, product=s.product, version=s.version)
            g.add_edge(ATTACKER, sid, kind="reach")
            g.add_edge(sid, h.ip, kind="compromise")

    # Lateral movement: a host can reach services on other hosts
    for a in hosts:
        for b in hosts:
            if a.ip == b.ip:
                continue
            for s in b.services:
                g.add_edge(a.ip, service_id(b, s), kind="lateral")

    return g


def paths_to_hosts(g, max_paths_per_host=50):
    """Return all simple paths from the attacker to each host."""
    result = {}
    for node, data in g.nodes(data=True):
        if data.get("kind") == "host":
            paths = nx.all_simple_paths(g, ATTACKER, node)
            result[node] = [p for _, p in zip(range(max_paths_per_host), paths)]
    return result


if __name__ == "__main__":
    hosts = parse_nmap_xml(sys.argv[1])
    g = build_graph(hosts)
    print(f"Nodes: {g.number_of_nodes()}  Edges: {g.number_of_edges()}")
    for host, paths in paths_to_hosts(g).items():
        print(f"\n{host}: {len(paths)} path(s) from attacker")
        for p in paths[:5]:
            print("  " + " -> ".join(p))
