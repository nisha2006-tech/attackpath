# AttackPath

AI-assisted attack path prioritization for red teams. It reads an Nmap scan, builds an attack graph, scores each path using service type, known CVEs and CVSS, and ranks the paths with a reason for each one.

> For authorized security testing only. Use it only on systems you own or have written permission to test.

## How it works

1. Ingest an Nmap XML scan (nmap -sV -oX scan.xml TARGET)
2. Build an attack graph (attacker, services, hosts)
3. Score each service by likelihood and impact, with a boost for known CVEs (CVSS from NVD, cached locally)
4. Rank the paths and write an HTML or JSON report

## Install

    git clone https://github.com/nisha2006-tech/attackpath.git
    cd attackpath
    python3 -m venv venv && source venv/bin/activate
    pip install -r requirements.txt

## Usage

    pip install -e .
    attackpath samples/sample_scan.xml --top 10 --out report.html --json results.json

## Evaluation

Three targets: Metasploitable 2 (23 services), two Docker labs (7 and 6 services). Ground truth was written by the author before running the tool on each target. Metrics: Precision@5 and Average Precision (AP).

| Target | Random AP | CVSS only AP | AttackPath AP | ML AP (leave-one-target-out) |
|---|---|---|---|---|
| T1 Metasploitable 2 (rules written for it) | 0.615 | 0.641 | 0.908 | 0.523 |
| T2 Docker lab 1 (dev set for v2 rules) | 0.792 | 0.853 | 0.903 | 0.810 |
| T3 Docker lab 2 (held out) | 0.637 | 0.722 | 0.411 | 0.639 |

Findings:

- The hand-written rules work on the lab they were written for and fail on the unseen target (T3, below random).
- A small logistic regression trained on the other targets did better than the rules on T3, but is weak on T1.
- The CVSS-only score on T3 is a tie-break artifact: no CVEs matched, so ties were broken by port number.
- Only 36 services in total, so all differences are noisy. These results validate the pipeline and are not a general claim.

Reproduce:

    python -m attackpath.compare samples/target3_scan.xml data/ground_truth_target3.json
    python -m attackpath.ml_eval

## Limitations

- Ground truth labels are by the author, with no independent labelling
- Two of three targets are Docker containers on one host, not a real network
- Banner scanning cannot see weak or missing authentication
- Rule table is hand-set and does not generalize to unseen services

## Roadmap

- [x] Parser, attack graph, scoring, CVE/CVSS data, HTML report, tests
- [x] Baselines and leave-one-target-out ML evaluation
- [ ] More targets and independent ground truth
- [ ] Better features (version age, authentication checks)
- [ ] Docker image

## Status

Final-year project, work in progress.
