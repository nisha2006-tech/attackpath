# service name: (likelihood 0-1, impact 0-10)
SERVICE_RISK = {
    "telnet": (0.9, 9), "login": (0.9, 9), "shell": (0.9, 9), "exec": (0.9, 9),
    "vnc": (0.7, 9), "microsoft-ds": (0.7, 9), "netbios-ssn": (0.6, 8),
    "ftp": (0.7, 7), "nfs": (0.6, 8), "rmiregistry": (0.7, 8),
    "mysql": (0.5, 8), "postgresql": (0.5, 8), "ssh": (0.3, 8),
    "http": (0.5, 6), "https": (0.4, 6), "ajp13": (0.5, 6),
    "irc": (0.5, 6), "smtp": (0.4, 5), "domain": (0.3, 5), "x11": (0.4, 6),
}
DEFAULT_RISK = (0.3, 4)

# product/version fragments known to be outdated or weak: (text, likelihood boost)
KNOWN_WEAK = [
    ("vsftpd 2.3.4", 0.2), ("unrealircd", 0.2), ("samba 3.0", 0.2),
    ("distccd", 0.2), ("proftpd 1.3.1", 0.1), ("openssh 4.", 0.1),
    ("apache httpd 2.2", 0.1), ("tomcat", 0.1),
]


def score_node(data):
    """Score one service node. Returns likelihood, impact, score and reasons."""
    name = data.get("name", "").lower()
    likelihood, impact = SERVICE_RISK.get(name, DEFAULT_RISK)
    reasons = [f"{name or 'unknown'} service (base {likelihood}/{impact})"]

    banner = f"{data.get('product', '')} {data.get('version', '')}".lower()
    for text, boost in KNOWN_WEAK:
        if text in banner:
            likelihood = min(1.0, likelihood + boost)
            reasons.append(f"outdated/weak version: {text}")

    return {"likelihood": round(likelihood, 2), "impact": impact,
            "score": round(likelihood * impact, 2), "reasons": reasons}

# Names Nmap reports that the table above did not cover
SERVICE_RISK.update({
    "bindshell": (1.0, 10),
    "java-rmi": (0.7, 8),
    "rpcbind": (0.4, 5),
})
