# Chapter 8: Conclusion and future work

## 8.1 Summary
This project built AttackPath, a command-line tool that turns an Nmap scan into a ranked list of attack paths with a reason for each score. It uses service type, weak-version matches and CVE and CVSS data from NVD. The tool was evaluated on three lab targets against random, CVSS-only and CVSS-plus-service-type baselines, and a small logistic regression model was tested with leave-one-target-out validation.

## 8.2 Findings
The hand-written rules ranked the first lab very well but did not generalize: on the held-out target their average precision (0.411) was below the random average (0.637). A small learned model did better on that target (0.639) but was weaker on the first lab. The result of the CVSS-only baseline on the held-out target was an artifact of ties between services with no CVE.

## 8.3 Limitations
The study has only 36 services in three targets, the ground truth was written by the author, two targets are single-host Docker labs, and banner scanning cannot see weak authentication.

## 8.4 Future work
- More targets, including multi-host networks, and independent labelling of the ground truth.
- Better features such as version age, exploit availability and authentication checks.
- Exploit prediction data such as EPSS as an additional signal.
- A larger training set so that learned and hand-written scoring can be compared fairly.
- A packaged release, for example a Docker image.
