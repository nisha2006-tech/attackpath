# Chapter 4: System design

## 4.1 Overview
(2-3 sentences: input is an Nmap scan, output is a ranked list of attack paths with reasons. Insert docs/architecture.md diagram here.)

## 4.2 Ingest module
- Reads Nmap XML (nmap -sV -oX), keeps hosts that are up and ports that are open
- Per service: port, protocol, service name, product, version

## 4.3 Attack graph
- Directed graph (NetworkX): attacker -> service -> host
- Lateral edges: host -> services on other hosts
- Paths enumerated from attacker to each host (capped at 50 per host)

## 4.4 Scoring
- Base likelihood and impact per service type (rule table)
- Boost for known weak versions
- CVE data: banner keyword -> CVE ids -> CVSS from NVD, cached locally
- Path score = product of likelihoods x impact of the final service
- Reasons stored per path, so each ranking is explainable

## 4.5 Reporting
- HTML report (Jinja2) with color-coded score and the reasons; JSON output

## 4.6 Evaluation framework
- Metrics: Precision@5, Average Precision (P@10 not primary)
- Baselines: random, CVSS only, CVSS + service type
- Three targets: Metasploitable 2, Docker lab 1, Docker lab 2
- Ground truth written before each run
- ML: logistic regression, leave-one-target-out, features in data/features.csv

## 4.7 Design limitations
- Heuristic weights, no exploit execution, banner scan only
- Single host per target in two of three targets
