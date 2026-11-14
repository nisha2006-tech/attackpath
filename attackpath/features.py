import csv
import json
from pathlib import Path

from attackpath.ingest import parse_nmap_xml
from attackpath.graph import build_graph
from attackpath.evaluate import port_of, cvss_of

TARGETS = [
    ("target1", "samples/sample_scan.xml", "data/ground_truth.json"),
    ("target2", "samples/target2_scan.xml", "data/ground_truth_target2.json"),
    ("target3", "samples/target3_scan.xml", "data/ground_truth_target3.json"),
]

# generic service groups, matched by substring of the Nmap service name
GROUPS = {
    "web": ["http", "ajp"],
    "database": ["sql", "oracle"],
    "remote_access": ["ssh", "telnet", "vnc", "login", "shell", "exec", "x11"],
    "file_share": ["ftp", "nfs", "netbios", "microsoft-ds", "smb"],
    "data_store": ["redis", "mongo", "memcache", "mqtt", "mosquitto", "rmi"],
}

COLUMNS = ["target", "port", "name", "label", "port_low", "has_version",
           "has_cve", "max_cvss"] + ["grp_" + g for g in GROUPS]


def rows_for(target, scan, truth_file):
    g = build_graph(parse_nmap_xml(scan))
    truth = set(json.loads(Path(truth_file).read_text())["ports"])
    out = []
    for node, d in g.nodes(data=True):
        if d.get("kind") != "service":
            continue
        name = d.get("name", "").lower()
        port = port_of(node)
        cvss = cvss_of(d)
        row = {
            "target": target, "port": port, "name": name,
            "label": int(port in truth),
            "port_low": int(port < 1024),
            "has_version": int(bool((d.get("product") or "").strip() or (d.get("version") or "").strip())),
            "has_cve": int(cvss > 0),
            "max_cvss": cvss,
        }
        for grp, keys in GROUPS.items():
            row["grp_" + grp] = int(any(k in name for k in keys))
        out.append(row)
    return out


if __name__ == "__main__":
    rows = []
    for t in TARGETS:
        rows += rows_for(*t)
    with open("data/features.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {len(rows)} rows, {sum(r['label'] for r in rows)} positives")
