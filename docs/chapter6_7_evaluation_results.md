# Chapter 6: Evaluation setup

## 6.1 Research questions
1. Does path-based scoring rank easy-to-exploit services higher than CVSS alone?
2. Do hand-written rules generalize to targets they were not written for?
3. Can a small learned model do better than the rules on an unseen target?

## 6.2 Targets and ground truth
| Target | Services | Positives | Role |
|---|---|---|---|
| T1 Metasploitable 2 | 23 | 13 | Rules written with this lab in mind (not held out) |
| T2 Docker lab 1 | 7 | 5 | Development set for v2 rules (redis, mongodb) |
| T3 Docker lab 2 | 6 | 3 | Held-out test set |

- A positive is a service that is easy to exploit (default or no authentication, known backdoor or RCE)
- Ground truth was written by the author before running the tool on each target
- Limitation: no independent labels

## 6.3 Methods compared
Random (1000 shuffles), CVSS only, CVSS + service type, AttackPath (hand rules), ML (logistic regression, leave-one-target-out)

## 6.4 Metrics
Precision@5 and Average Precision. P@10 is reported but is capped by the number of services on small targets.

# Chapter 7: Results and discussion

## 7.1 Results
| Target | Method | P@5 | AP |
|---|---|---|---|
| T1 | Random | 0.55 | 0.615 |
| T1 | CVSS only | 0.60 | 0.641 |
| T1 | CVSS + service type | 1.00 | 0.927 |
| T1 | AttackPath | 1.00 | 0.908 |
| T2 | Random | 0.71 | 0.792 |
| T2 | CVSS only | 0.80 | 0.853 |
| T2 | CVSS + service type | 0.80 | 0.786 |
| T2 | AttackPath | 0.80 | 0.903 |
| T3 | Random | 0.49 | 0.637 |
| T3 | CVSS only | 0.40 | 0.722 |
| T3 | CVSS + service type | 0.40 | 0.467 |
| T3 | AttackPath | 0.40 | 0.411 |

ML (leave-one-target-out): T1 P@5 0.40 AP 0.523, T2 P@5 0.80 AP 0.810, T3 P@5 0.60 AP 0.639.

## 7.2 Discussion (write one paragraph per point, in your own words)
- Rules fit the lab they were written for (T1) and fail on the unseen target (T3, AP below random)
- ML trained on other targets did better than the rules on T3 but was weak on T1 (only 13 training rows)
- On T1, AttackPath matches CVSS + service type, so path scoring and the CVE boost added nothing measurable
- CVSS-only AP of 0.722 on T3 is a tie-break artifact: all CVSS values are 0 and ties are broken by port number
- P@10 is capped by service count, so P@5 and AP are the main metrics
- Averaging across folds is not fair, because T1 and T2 were not held out for the rules

## 7.3 Threats to validity
- 36 services in total, so every difference is noisy
- Ground truth by the author
- T2 and T3 are Docker containers on one host, not a real network
- Banner scanning cannot see weak or missing authentication

## 7.4 What the results mean
(2 or 3 sentences: the pipeline works and is explainable, but hand-set rules do not generalize. More targets and data are needed before any claim about learned ranking.)
