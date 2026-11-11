import json
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"

# service name: (likelihood 0-1, impact 0-10)
SERVICE_RISK = {
    "bindshell": (1.0, 10),
    "telnet": (0.9, 9), "login": (0.9, 9), "shell": (0.9, 9), "exec": (0.9, 9),
    "vnc": (0.7, 9), "microsoft-ds": (0.7, 9), "netbios-ssn": (0.6, 8),
    "ftp": (0.7, 7), "nfs": (0.6, 8), "rmiregistry": (0.7, 8), "java-rmi": (0.7, 8),
    "mysql": (0.5, 8), "postgresql": (0.5, 8), "ssh": (0.3, 8),
    "http": (0.5, 6), "https": (0.4, 6), "ajp13": (0.5, 6),
    "irc": (0.5, 6), "smtp": (0.4, 5), "domain": (0.3, 5), "x11": (0.4, 6),
    "rpcbind": (0.4, 5),
}
DEFAULT_RISK = (0.3, 4)

# product/version fragments known to be outdated or weak: (text, likelihood boost)
KNOWN_WEAK = [
    ("proftpd 1.3.1", 0.1), ("openssh 4.", 0.1),
    ("apache httpd 2.2", 0.1), ("tomcat", 0.1),
]


def _load(name):
    f = DATA / name
    return json.loads(f.read_text()) if f.exists() else {}


CVE_MAP = _load("cve_map.json")
CVSS_CACHE = _load("cvss_cache.json")


def score_node(data):
    """Score one service node using base risk, weak versions and known CVEs."""
    name = data.get("name", "").lower()
    likelihood, impact = SERVICE_RISK.get(name, DEFAULT_RISK)
    reasons = [f"{name or 'unknown'} service (base {likelihood}/{impact})"]

    banner = f"{data.get('product', '')} {data.get('version', '')}".lower()

    for text, boost in KNOWN_WEAK:
        if text in banner:
            likelihood = min(1.0, likelihood + boost)
            reasons.append(f"outdated/weak version: {text}")

    for keyword, cves in CVE_MAP.items():
        if keyword in banner:
            for cve_id in cves:
                info = CVSS_CACHE.get(cve_id, {})
                cvss = info.get("cvss")
                likelihood = min(1.0, likelihood + 0.2)
                if cvss:
                    impact = max(impact, round(cvss))
                    reasons.append(f"{cve_id} (CVSS {cvss})")
                else:
                    reasons.append(f"{cve_id} (CVSS not cached)")

    return {"likelihood": round(likelihood, 2), "impact": impact,
            "score": round(likelihood * impact, 2), "reasons": reasons}
