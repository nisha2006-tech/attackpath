from attackpath.ingest import parse_nmap_xml
from attackpath.graph import build_graph
from attackpath.ranker import rank_paths

SAMPLE = "samples/sample_scan.xml"


def test_parser_finds_host_and_services():
    hosts = parse_nmap_xml(SAMPLE)
    assert len(hosts) == 1
    assert len(hosts[0].services) > 10


def test_graph_has_attacker_and_hosts():
    g = build_graph(parse_nmap_xml(SAMPLE))
    assert "attacker" in g.nodes
    assert any(d.get("kind") == "host" for _, d in g.nodes(data=True))


def test_ranking_is_sorted_and_bindshell_first():
    g = build_graph(parse_nmap_xml(SAMPLE))
    ranked = rank_paths(g, 10)
    scores = [r["score"] for r in ranked]
    assert scores == sorted(scores, reverse=True)
    assert "1524/tcp" in ranked[0]["path"][1]
