# Report notes (running log)

## Setup
- Target 1: Metasploitable 2 (23 services), ground truth 13 easy-exploit services
- Target 2: Docker lab (7 services), ground truth 5, written BEFORE running the tool
- Baselines: CVSS-only (ties broken by port number), random (1000 shuffles)

## Results v1 (hand-set rules)
- Target 1: AttackPath P@5 1.0, AP 0.908 vs CVSS baseline P@5 0.6, AP 0.641
- Target 2: AttackPath P@5 0.6, AP 0.73 | CVSS baseline P@5 0.8, AP 0.853 | random P@5 0.71, AP 0.781

## Findings
- Rules were written with Metasploitable in mind, so target 1 results are optimistic
- On target 2, AttackPath scored below random: no rules for redis, mongodb, web apps (Nmap reported Juice Shop as ppp?)
- PostgreSQL (strong password) and nginx ranked high: false positives
- CVSS baseline win on target 2 is a tie-break artifact (all CVSS 0, ordered by port)
- Banner scanning cannot detect weak or missing authentication
- Target 2 is small (7 services), so metrics are noisy

## Next
- Improve rules using target 2 as dev set, test on an unseen target (test set)
- ML model with leave-one-target-out evaluation

## Final results (v2 rules, 3 targets)

Target 3 is the only target held out from rule writing. Target 1: rules written for it. Target 2: dev set for v2 rules.

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
| T3 | CVSS only | 0.40 | 0.722 (port-order tie artifact) |
| T3 | CVSS + service type | 0.40 | 0.467 |
| T3 | AttackPath | 0.40 | 0.411 |

ML (logistic regression, leave-one-target-out): T1 P@5 0.40 AP 0.523; T2 P@5 0.80 AP 0.810; T3 P@5 0.60 AP 0.639.

## Findings
- Hand-set rules fit the lab they were written for (T1) and fail on the unseen target (T3, AP below random)
- ML trained on other targets beats the hand rules on T3 but is weak on T1 (only 13 training rows)
- On T1, AttackPath equals CVSS + service type: path scoring and CVE boost add nothing measurable
- CVSS-only on T3 equals port-order ranking (all CVSS 0): AP 0.722 is a tie-break artifact
- P@10 is capped by service count (T3: max 0.3), so P@5 and AP are the primary metrics
- Mean across folds is not a fair comparison because rule-based folds T1 and T2 were not held out
- 36 services in total, so all differences are noisy
