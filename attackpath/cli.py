import argparse
from attackpath.ingest import parse_nmap_xml
from attackpath.graph import build_graph
from attackpath.ranker import rank_paths
from attackpath.report import write_html, write_json


def main():
    parser = argparse.ArgumentParser(
        prog="attackpath",
        description="Rank attack paths from an Nmap XML scan. Use only on systems you are authorized to test.")
    parser.add_argument("scan", help="Nmap XML file (from nmap -sV -oX ...)")
    parser.add_argument("--top", type=int, default=10, help="number of paths to show (default 10)")
    parser.add_argument("--out", default="report.html", help="HTML report file (default report.html)")
    parser.add_argument("--json", dest="json_out", help="also write results to this JSON file")
    args = parser.parse_args()

    hosts = parse_nmap_xml(args.scan)
    if not hosts:
        raise SystemExit("No live hosts found in the scan file.")

    g = build_graph(hosts)
    ranked = rank_paths(g, args.top)

    write_html(ranked, args.out, args.scan, len(hosts))
    if args.json_out:
        write_json(ranked, args.json_out)

    print(f"Hosts: {len(hosts)}  Paths ranked: {len(ranked)}")
    for i, r in enumerate(ranked[:3], 1):
        print(f"  #{i} score={r['score']}  {' -> '.join(r['path'])}")
    print(f"Report written to {args.out}")


if __name__ == "__main__":
    main()
