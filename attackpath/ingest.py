import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


@dataclass
class Service:
    port: int
    protocol: str
    name: str
    product: str = ""
    version: str = ""


@dataclass
class Host:
    ip: str
    hostname: str = ""
    services: list = field(default_factory=list)


def parse_nmap_xml(path):
    """Read an Nmap XML file and return a list of Host objects."""
    root = ET.parse(path).getroot()
    hosts = []

    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addr = h.find("address[@addrtype='ipv4']")
        if addr is None:
            continue

        hn = h.find("hostnames/hostname")
        host = Host(ip=addr.get("addr"),
                    hostname=hn.get("name") if hn is not None else "")

        for p in h.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            host.services.append(Service(
                port=int(p.get("portid")),
                protocol=p.get("protocol"),
                name=svc.get("name", "unknown") if svc is not None else "unknown",
                product=svc.get("product", "") if svc is not None else "",
                version=svc.get("version", "") if svc is not None else "",
            ))
        hosts.append(host)

    return hosts


if __name__ == "__main__":
    for host in parse_nmap_xml(sys.argv[1]):
        print(f"Host {host.ip} ({len(host.services)} open services)")
        for s in host.services:
            print(f"  {s.port}/{s.protocol}  {s.name}  {s.product} {s.version}")
