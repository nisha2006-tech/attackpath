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
