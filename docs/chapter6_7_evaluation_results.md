# Chapter 6: Evaluation setup

## 6.1 Research questions
1. Does path-based scoring rank easy-to-exploit services higher than CVSS alone?
2. Do hand-written rules generalize to targets they were not written for?
3. Can a small learned model do better than the rules on an unseen target?

## 6.2 Targets and ground truth
Three targets were used. A service is labelled positive when it is easy to exploit, for example because it has default or no authentication, a known backdoor, or a known remote code execution flaw. The labels were written by the author before the tool was run on each target.

| Target | Services | Positives | Role in the study |
|---|---|---|---|
| T1 Metasploitable 2 | 23 | 13 | Rules were first written while looking at this lab, so it is not held out |
| T2 Docker lab 1 | 7 | 5 | Development set: the v2 rules for Redis and MongoDB were added after seeing it |
| T3 Docker lab 2 | 6 | 3 | Held-out test set: no rule was written or changed after it was scanned |

## 6.3 Methods compared
- Random: the average over 1000 random orderings.
- CVSS only: services sorted by the highest CVSS score of a matching CVE; services with no CVE score 0 and ties are broken by port number.
- CVSS plus service type: CVSS first, then the impact value from the rule table.
- AttackPath: the full hand-written scoring and path ranking.
- ML: a logistic regression model trained on the services of the other two targets and tested on the held-out target (leave-one-target-out). Features are service group, whether a version was detected, whether a CVE matched, the CVSS value and whether the port is below 1024.

## 6.4 Metrics
Services are ranked and compared with the ground truth using Precision@5 (the share of the top five that are positive) and Average Precision (AP), which rewards putting positives early. Precision@10 is computed but not used as a main metric, because T2 and T3 have fewer than ten services and the value is capped by the number of services.

# Chapter 7: Results and discussion

## 7.1 Results
| Target | Method | P@5 | AP |
|---|---|---|---|
| T1 | Random | 0.55 | 0.615 |
| T1 | CVSS only | 0.60 | 0.641 |
| T1 | CVSS + service type | 1.00 | 0.927 |
| T1 | AttackPath | 1.00 | 0.908 |
| T1 | ML (leave-one-target-out) | 0.40 | 0.523 |
| T2 | Random | 0.71 | 0.792 |
| T2 | CVSS only | 0.80 | 0.853 |
| T2 | CVSS + service type | 0.80 | 0.786 |
| T2 | AttackPath | 0.80 | 0.903 |
| T2 | ML (leave-one-target-out) | 0.80 | 0.810 |
| T3 (held out) | Random | 0.49 | 0.637 |
| T3 (held out) | CVSS only | 0.40 | 0.722 |
| T3 (held out) | CVSS + service type | 0.40 | 0.467 |
| T3 (held out) | AttackPath | 0.40 | 0.411 |
| T3 (held out) | ML (leave-one-target-out) | 0.60 | 0.639 |

## 7.2 Discussion
**Rules fit the lab they were written for.** On T1 the AttackPath rules reach a P@5 of 1.00 and an AP of 0.908, well above random (0.615) and CVSS only (0.641). This result is optimistic, because the rule table was first written while looking at this lab.

**Rules did not generalize.** On the held-out T3 the AttackPath AP is 0.411, below the random average of 0.637. Memcached, the MQTT broker and the Docker registry had no rule and received the default score, while MariaDB and Tomcat, which are safe in this setup, matched rules with high scores.

**The learned model did better on the unseen target.** Trained on T1 and T2, the logistic regression reached a P@5 of 0.60 and an AP of 0.639 on T3, compared with 0.40 and 0.411 for the rules. On T1, however, it was weaker than the rules (AP 0.523 against 0.908), which is expected because it was trained on only the 13 services of T2 and T3.

**Path scoring added little on T1.** AttackPath (AP 0.908) did not beat CVSS plus service type (AP 0.927). On single hosts every path has the same shape, so the extra path product and the CVE boost did not change the order in a measurable way.

**The CVSS-only result on T3 is an artifact.** None of the T3 services matched a CVE, so all CVSS values were 0 and the order was decided by port number. The resulting AP of 0.722 does not show that CVSS is a good predictor here.

**Averaging across targets would be misleading.** The rule-based methods were not held out on T1 and T2, so a mean over the three targets would compare unequal things. T3 is the only target where all methods are on equal terms.

## 7.3 Threats to validity
- The study covers 36 services in total, so every difference is noisy and no statistical claim is made.
- The ground truth was written by the author and was not labelled independently.
- T2 and T3 are Docker containers on one host, not a real network, so lateral movement was not tested.
- Banner scanning cannot see weak or missing authentication, which limits what any method based on it can achieve.
- Ties are broken by port number in every method.

## 7.4 Summary
The pipeline works and produces explainable rankings, but the hand-written rules did not carry over to a target they were not written for. A small learned model did better on that target but was weaker on the first lab. More targets, independent labels and better features, such as authentication checks and version age, are needed before any general claim about learned ranking can be made.
