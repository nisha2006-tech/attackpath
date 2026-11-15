# Chapter 2: Literature review

## 2.1 Attack graphs and attack path modelling
Attack graphs describe how an attacker can move from an initial state to a goal state, where nodes represent system states and edges represent transitions caused by attacker actions [1]. Attack trees place the attacker's goal at the root and break it into sub-goals joined by AND and OR nodes [1]. The survey by Haque et al. reports that graph-based methods struggle to scale to large networks because of state explosion, and that logic-based generation depends heavily on rules and vulnerability data supplied by the administrator [1]. Some of the surveyed work uses CVSS scores as the basis for probabilities in Bayesian attack graphs [1]. AttackPath uses a much simpler graph built from a single Nmap scan, and focuses on ranking and explaining paths rather than on exhaustive generation.

## 2.2 Vulnerability scoring: CVSS and EPSS
(Write after Paper 3.)

## 2.3 Existing tools
(Write after you read the BloodHound documentation.)

## 2.4 Machine learning in penetration testing
(Write after Paper 2.)

## 2.5 Gap addressed by this project
(2 or 3 sentences.)

## References
[1] S. Haque, M. Keffeler, and T. Atkison, "An evolutionary approach of attack graphs and attack trees: A survey of attack modeling," in Proc. Int. Conf. Security and Management (SAM'17), CSREA Press, 2017, pp. 224-229.
