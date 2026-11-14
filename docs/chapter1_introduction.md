# Chapter 1: Introduction

## 1.1 Background
(3 to 4 sentences: red teams and penetration testers get long lists of open services and vulnerabilities, and have limited time.)

## 1.2 Problem statement
(Write in your own words. Points to cover: severity scores such as CVSS rate one vulnerability at a time and do not show how services combine into a path to a host; testers prioritize by experience, which is slow and inconsistent.)

## 1.3 Objectives
1. Build a tool that turns an Nmap scan into a ranked list of attack paths with reasons
2. Use CVE and CVSS data in the scoring
3. Evaluate it against baselines on more than one target
4. Test whether a small learned model can replace hand-written rules

## 1.4 Scope
- In scope: network service exposure from Nmap scans, scoring and ranking, evaluation in a lab
- Out of scope: exploit execution, web application testing, cloud environments

## 1.5 Contributions
(Short and honest: working open-source tool, evaluation protocol with ground truth written before running, and a negative result on rule generalization.)

## 1.6 Ethics
Authorized-use only. All tests were run on lab machines owned by the author.

## 1.7 Report organization
(One line per chapter: 2 literature review, 3 requirements, 4 design, 5 implementation, 6 evaluation setup, 7 results, 8 conclusion.)
