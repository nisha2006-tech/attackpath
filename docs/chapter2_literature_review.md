# Chapter 2: Literature review

## 2.1 Attack graphs and attack path modelling
Attack graphs describe how an attacker can move from an initial state to a goal state, where nodes represent system states and edges represent transitions caused by attacker actions [1]. Attack trees place the attacker's goal at the root and break it into sub-goals joined by AND and OR nodes [1]. The survey by Haque et al. reports that graph-based methods struggle to scale to large networks because of state explosion, and that logic-based generation depends heavily on rules and vulnerability data supplied by the administrator [1]. Some of the surveyed work uses CVSS scores as the basis for probabilities in Bayesian attack graphs [1]. AttackPath uses a much simpler graph built from a single Nmap scan, and focuses on ranking and explaining paths rather than on exhaustive generation.

## 2.2 Vulnerability scoring: CVSS and EPSS
(Write after Paper 3.)

## 2.3 Existing tools
(Write after you read the BloodHound documentation.)

## 2.4 Machine learning in penetration testing
Tools such as Nmap and Metasploit automate parts of a penetration test, but an experienced tester is still needed to interpret their output [2]. Penetration path planning, the task of choosing the route from an entry point to a target, has therefore become a research topic in automated penetration testing [2]. Chen et al. group the methods into intelligent planning, reinforcement learning and planning with large language models [2]. Reinforcement learning agents are trained in simulated environments, and the survey lists the gap between such simulations and real networks as an open challenge [2]. The same survey also reports work arguing that attack graphs based on CVSS alone do not capture the real structure of a target network [2]. AttackPath differs from these approaches: it does not execute attacks or train an agent in a simulator, but ranks the services of a real scan and explains each ranking.

## 2.5 Gap addressed by this project
(2 or 3 sentences.)

## References
[1] S. Haque, M. Keffeler, and T. Atkison, "An evolutionary approach of attack graphs and attack trees: A survey of attack modeling," in Proc. Int. Conf. Security and Management (SAM'17), CSREA Press, 2017, pp. 224-229.

[2] Z. Chen, F. Kang, X. Xiong, and H. Shu, "A survey on penetration path planning in automated penetration testing," Appl. Sci., vol. 14, no. 18, Art. no. 8355, 2024, doi: 10.3390/app14188355.
