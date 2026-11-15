# Viva questions (write your own 2-3 sentence answers)

## Basics
1. What problem does AttackPath solve? Why is CVSS alone not enough?
2. Walk through what happens from the Nmap scan to the report.
3. What is an attack graph? What are your nodes and edges?
4. Why did you use Nmap XML as input?

## Scoring
5. How is a path score calculated? Why multiply the likelihoods?
6. Where do the rule values (likelihood, impact) come from? Are they scientific?
7. What does the CVE map do? Where does CVSS come from?
8. What is the difference between CVSS v2 and v3? Which did you use?

## Evaluation
9. What is ground truth here and who wrote it? What is the weakness of that?
10. Why did you write the ground truth before running the tool?
11. What are Precision@5 and Average Precision?
12. Why does AttackPath beat the baselines on Target 1 but not on Target 3?
13. Why is the CVSS-only result on Target 3 an artifact?
14. Why is averaging the three targets not fair?
15. Why did you add rules only from Target 2 and keep Target 3 untouched?

## Machine learning
16. Which model did you use and why logistic regression?
17. What is leave-one-target-out validation?
18. Your data has only 36 services. What can you conclude and what can't you?
19. Why did the ML model do worse than the rules on Target 1?

## Limitations and ethics
20. What can't your tool detect? (authentication, exploit availability)
21. Two targets are Docker containers on one host. What does that miss?
22. Is the tool legal? How did you make sure you only scanned your own machines?
23. What would you do next with more time?

## Practical
24. How do I run your tool? Demo it.
25. Why did you replace the OWASP BWA target?
