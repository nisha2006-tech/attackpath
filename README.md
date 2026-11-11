# AttackPath

AI-assisted attack path prioritization for red teams. Takes an Nmap scan, builds an attack graph, and ranks the most promising paths with an explanation for each.

> For authorized security testing only. Use it only on systems you own or have written permission to test.

## How it works

1. **Ingest** an Nmap XML scan (`nmap -sV -oX scan.xml <target>`)
2. **Build** an attack graph (attacker, services, hosts)
3. **Score** each service by likelihood and impact
4. **Rank** paths and write an HTML or JSON report

## Install

```bash
git clone https://github.com/nisha2006-tech/attackpath.git
cd attackpath
python3 -m venv venv && source venv/bin/activate
pip install networkx jinja2 scikit-learn
```

## Usage

```bash
python -m attackpath samples/sample_scan.xml --top 10 --out report.html --json results.json
```

## Roadmap

- [x] Nmap parser, attack graph, heuristic scoring, HTML report
- [ ] CVE/CVSS and EPSS data
- [ ] Machine learning ranking model
- [ ] Evaluation against a CVSS baseline
- [ ] Tests and Docker image

## Status

Work in progress (final-year project).
