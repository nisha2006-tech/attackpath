# Chapter 5: Implementation

## 5.1 Environment
The tool was developed in Python 3 inside a Kali Linux virtual machine running on VirtualBox. The main libraries are NetworkX for the attack graph, Jinja2 for the HTML report, scikit-learn for the machine learning experiment and pytest for testing. Nmap was used to scan the lab targets. The code is kept under version control with Git and hosted on GitHub.

The lab had three targets: Metasploitable 2 running as a virtual machine on a host-only network, and two groups of Docker containers bound to 127.0.0.1 so that the vulnerable services were not exposed to any real network. The Kali machine had two network adapters: NAT for internet access and host-only for reaching the lab.

## 5.2 Module overview
| Module | Purpose |
|---|---|
| ingest.py | Parses Nmap XML into Host and Service objects |
| graph.py | Builds the attack graph and enumerates paths |
| scoring.py | Rule table, weak-version boost, CVE and CVSS boost |
| fetch_cvss.py | Downloads CVSS scores from the NVD API and caches them |
| ranker.py | Scores and sorts the paths |
| report.py, cli.py | HTML and JSON output, command-line interface |
| evaluate.py, compare.py, random_baseline.py | Metrics and baseline comparison |
| features.py, ml_eval.py | Feature table and leave-one-target-out learning experiment |

## 5.3 Key implementation details
**Parsing.** The parser uses the XML library from the Python standard library. It skips hosts that are not up and ports that are not open, and it fills missing product or version fields with empty strings.

**Graph construction.** Nodes carry a kind attribute (attacker, service or host) and service nodes also store the port, service name, product and version. Edges carry a kind attribute (reach, compromise or lateral). Paths are found with the simple-path search of NetworkX and limited to 50 per host.

**Scoring.** The scoring function returns the likelihood, impact, score and a list of reasons. The reasons are what make the output explainable: each path in the report shows why it received its score.

**CVE data.** CVSS scores are downloaded once from the NVD API by fetch_cvss.py and stored in a local JSON cache. During a normal run the tool reads only the cache, so it works offline and does not exceed the NVD rate limit. A small mapping file links banner keywords to CVE identifiers.

## 5.4 Command-line usage
The tool is run as a Python module:

    python -m attackpath samples/sample_scan.xml --top 10 --out report.html --json results.json

(Insert the screenshot docs/report.png here.)

## 5.5 Testing
Automated tests written with pytest check that the parser finds the host and its services, that the graph contains the attacker and host nodes, and that the ranking is sorted with the most exposed service first. (If you added tests/test_scoring.py, add one sentence about the scoring tests.) The complete pipeline was also run by hand on all three targets. The tests do not yet cover the CVSS download script.

## 5.6 Problems faced and how they were solved
**Unrecognized services.** Nmap reported the Juice Shop web application on port 3000 as an unknown service, so no rule matched it and it received the default score. This is one of the reasons the hand-written rules do not generalize.

**CVSS versions.** NVD returns CVSS v3 scores for newer CVEs and only v2 scores for old ones. The tool uses v3.1, then v3.0, then v2. The two versions are calculated differently, so scores from different versions are not strictly comparable. This is noted as a limitation.

**Missing CVE matches.** Many services on the Docker targets matched no CVE, so every CVSS value was 0 and the CVSS-only baseline fell back to port-number order. Its good score on one target is therefore an artifact of tie-breaking and is reported as such.

**Authentication cannot be seen from banners.** A PostgreSQL server with a strong password and an unauthenticated Redis server look similar in a banner scan. The tool cannot separate them, which causes false positives and misses.

**Network setup.** The Kali machine initially had only a host-only adapter, so it could reach the lab but not the internet and could not download packages or push to GitHub. Adding a second NAT adapter solved this. DNS resolution also failed once and was fixed by setting a public DNS server.

**Replacing a target.** The OWASP Broken Web Applications virtual machine was planned as an unseen test target, but its disk would not boot in VirtualBox after repeated attempts. A second set of Docker containers (memcached, mosquitto, Docker registry, Tomcat, MariaDB and Apache) was used instead. Its ground truth was written before it was scanned.

**Avoiding bias.** Because the rules were first written while looking at Metasploitable 2, results on that target were too optimistic. To reduce this, the ground truth for each new target was written before running the tool, v2 rules were added using only the development target, and the last target was kept untouched for testing.
