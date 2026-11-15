# Chapter 1: Introduction

## 1.1 Background
Penetration testers and red teams usually begin an engagement with a scan that returns a long list of open services and possible vulnerabilities. Time is limited, so the tester has to decide which exposed service to attack first. This decision is normally made from experience and from severity scores, and it is slow and not always consistent.

## 1.2 Problem statement
Severity scores such as CVSS rate a single vulnerability on its own. They do not describe how easy it is to reach and use a service, and many exposed services, for example a database or a message broker without authentication, have no CVE at all and so receive no score. As a result, a list sorted by CVSS can place a weak service below a harmless one. This project asks whether a tool that models services as paths to a host, and explains its ranking, can help a tester choose where to start.

## 1.3 Objectives
1. Build a tool that turns an Nmap scan into a ranked list of attack paths with reasons.
2. Use CVE and CVSS data in the scoring.
3. Evaluate the tool against baselines on more than one target.
4. Test whether a small learned model can replace the hand-written rules.

## 1.4 Scope
In scope: network service exposure found by Nmap scans, scoring and ranking of paths, and evaluation in a controlled lab. Out of scope: running exploits, web application testing and cloud environments.

## 1.5 Contributions
- A working command-line tool with HTML and JSON reports, published on GitHub.
- An evaluation protocol in which the ground truth for each target is written before the tool is run.
- An honest negative result: rules written for one lab did not generalize to an unseen target, and a small learned model was better there but weaker on the first lab.

## 1.6 Ethics
The tool is for authorized security testing only. All scans in this project were run on lab machines owned by the author.

## 1.7 Report organization
Chapter 2 reviews related work. Chapter 3 gives the requirements. Chapter 4 describes the design and Chapter 5 the implementation. Chapter 6 explains the evaluation setup and Chapter 7 presents the results. Chapter 8 concludes and lists future work.
