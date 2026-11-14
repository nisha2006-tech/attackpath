# Chapter 5: Implementation

## 5.1 Environment
- Kali Linux VM (VirtualBox), Python 3, venv
- Libraries: NetworkX, Jinja2, scikit-learn, pytest
- Lab targets: Metasploitable 2 (VM), two Docker labs bound to 127.0.0.1
- Version control: Git and GitHub

## 5.2 Module overview
| Module | Purpose |
|---|---|
| ingest.py | Parse Nmap XML into Host and Service objects |
| graph.py | Build the attack graph and enumerate paths |
| scoring.py | Rule table, weak-version boost, CVE and CVSS boost |
| fetch_cvss.py | Download CVSS scores from NVD and cache them |
| ranker.py | Score and sort paths |
| report.py, cli.py | HTML and JSON output, command-line interface |
| evaluate.py, compare.py, random_baseline.py | Metrics and baselines |
| features.py, ml_eval.py | Feature table and leave-one-target-out ML |

## 5.3 Key implementation details
(Pick 3 to 4 and explain each in your own words, with a short code snippet from the repo.)
- Parsing: which XML elements are read, why closed ports are skipped
- Graph: node kinds (attacker, service, host), edge kinds (reach, compromise, lateral)
- Scoring: how likelihood and impact are combined, how CVE data changes a score
- Caching CVSS locally so the tool works offline and respects NVD rate limits

## 5.4 Command-line usage
(Paste the real command and a screenshot of docs/report.png.)

## 5.5 Testing
- pytest: 3 tests (parser, graph, ranking order), all passing
- Manual testing on three targets
- Gaps: no tests yet for scoring and CVSS fetch

## 5.6 Problems faced and how they were solved
(Honest short notes, for example: Nmap reports unknown web apps as ppp?, NVD returns CVSS v2 for old CVEs and v3 for newer ones, banner scans cannot see authentication.)
