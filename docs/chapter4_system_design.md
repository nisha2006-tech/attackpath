# Chapter 4: System design

## 4.1 Overview
AttackPath takes the XML output of an Nmap service scan (nmap -sV -oX) as input and produces a ranked list of attack paths as output. Each path starts at an attacker node, passes through one exposed service and ends at the host that service belongs to. Every path comes with a score and a list of reasons that explain it. The processing has five steps: the scan file is parsed, an attack graph is built, each service is scored, the paths are ranked, and the result is written as an HTML or JSON report.

## 4.2 Ingest module
The ingest module reads the Nmap XML file and keeps only hosts whose status is up and which have an IPv4 address. For each host it keeps the hostname when one is reported. Only ports in the open state are kept, because closed and filtered ports give an attacker no entry point. For every open port the module stores the port number, protocol, service name, product and version, using one Host object per machine and one Service object per open port. Missing fields such as an unknown version are stored as empty strings so that later modules do not need special cases.

## 4.3 Attack graph
The attack graph is a directed graph built with NetworkX. It has three kinds of nodes: a single attacker node, one service node for each open port (for example 192.168.56.101:21/tcp), and one host node for each machine. Edges represent possible moves. The attacker connects to every service (reach), every service connects to its own host (compromise), and a host connects to the services of other hosts (lateral movement). A path is a route from the attacker node to a host node. For each host the tool enumerates simple paths, capped at 50 per host to keep the search bounded.

## 4.4 Scoring
Each service node is scored with a likelihood between 0 and 1 and an impact between 0 and 10. The starting values come from a rule table keyed by service name, for example telnet and exec have high likelihood and impact, and unknown services receive a low default. Likelihood is increased for banners that match known weak versions. The banner is also matched against a CVE map. For every matching CVE the likelihood rises by 0.2 (capped at 1) and the impact becomes at least the rounded CVSS base score, which is read from a local cache filled from the NVD API. The score of a path is the product of the likelihoods of the services on it multiplied by the impact of its last service. The reasons behind each score are stored with the path, so every ranking can be explained.

## 4.5 Reporting
The ranked paths are written as an HTML report rendered with Jinja2. Each path appears as a card with its position, score, likelihood, impact and reasons, and the score badge is coloured red, orange or green by level. The same results can be written as a JSON file for use by other tools. The command-line interface accepts the scan file, the number of paths to show and the output file names.

## 4.6 Evaluation framework
The tool is evaluated against ground truth labels on three targets: Metasploitable 2, and two Docker labs. A service is labelled positive when it is easy to exploit, for example because it has no authentication or a known backdoor. The labels were written before the tool was run on each target. The methods compared are a random order, CVSS only, CVSS plus service type, the hand-written rules of AttackPath, and a logistic regression model trained on the other targets (leave-one-target-out). The main metrics are Precision@5 and Average Precision.

## 4.7 Design limitations
The scoring weights are set by hand and are not learned. The tool works only from banner information, so it cannot detect weak or missing authentication. It does not run exploits, and two of the three test targets are single hosts, so lateral movement was not tested in practice.
