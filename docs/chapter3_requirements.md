# Chapter 3: Requirements

## 3.1 Functional requirements
1. The tool shall read an Nmap XML scan produced with service detection.
2. The tool shall build an attack graph from the hosts and open services in the scan.
3. The tool shall score each service using its type, its version banner and matching CVE data.
4. The tool shall rank the attack paths and give the reasons for each score.
5. The tool shall write the result as an HTML report and optionally as JSON.
6. The project shall include an evaluation that compares the ranking with baselines using ground truth labels.

## 3.2 Non-functional requirements
- Explainability: every ranked path must show why it received its score.
- Offline use: CVSS data is cached locally, so a normal run needs no internet connection.
- Reproducibility: sample scans, ground truth files and result files are stored in the repository.
- Safety: the tool does not run exploits, and all testing was done on lab machines owned by the author.

## 3.3 Hardware and software
Kali Linux virtual machine (2 CPUs, 2 GB RAM), VirtualBox, Python 3 with NetworkX, Jinja2, scikit-learn and pytest, Nmap, Docker, Git and GitHub.
