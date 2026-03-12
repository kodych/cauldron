"""Rule-based host role classification.

Classifies hosts by analyzing open port patterns and service banners.
Designed for real-world pentest data: handles multi-role hosts, partial scans,
and high-port ephemeral services.

Rule-based engine runs first (fast, no API cost). AI classification
handles edge cases and is optional.
"""

from __future__ import annotations

from dataclasses import dataclass

from cauldron.graph.models import Host, HostRole, Service


@dataclass
class ClassificationResult:
    """Result of host classification."""

    role: HostRole
    confidence: float  # 0.0 - 1.0
    reasons: list[str]
    secondary_roles: list[HostRole]


# Port patterns for each role.
# Each entry: (set of indicator ports, minimum matches required, confidence boost)
ROLE_RULES: dict[HostRole, list[tuple[set[int], int, float]]] = {
    HostRole.DOMAIN_CONTROLLER: [
        # Strong DC indicators: Kerberos + LDAP + GC
        ({88, 389, 636, 3268}, 3, 0.95),
        # Kerberos + LDAP is enough
        ({88, 389}, 2, 0.85),
        # Kerberos + kpasswd + SMB (DC without LDAP in scan)
        ({88, 464, 445}, 3, 0.80),
    ],
    HostRole.MAIL_SERVER: [
        # Full mail stack (SMTP + POP3/IMAP)
        ({25, 110, 143, 587, 993, 995}, 3, 0.90),
        # SMTP + submission
        ({25, 587}, 2, 0.75),
        # SMTP + secure mail
        ({25, 465, 993}, 2, 0.80),
        # POP3/IMAP only (webmail backend)
        ({110, 143, 993, 995}, 2, 0.70),
    ],
    HostRole.DATABASE: [
        ({3306,}, 1, 0.85),    # MySQL
        ({5432,}, 1, 0.85),    # PostgreSQL
        ({1433,}, 1, 0.85),    # MSSQL
        ({1521,}, 1, 0.85),    # Oracle
        ({27017,}, 1, 0.80),   # MongoDB
        ({6379,}, 1, 0.80),    # Redis
        ({9200,}, 1, 0.75),    # Elasticsearch
        ({5984,}, 1, 0.75),    # CouchDB
        ({9042,}, 1, 0.75),    # Cassandra
    ],
    HostRole.WEB_SERVER: [
        # Standard web ports
        ({80, 443}, 2, 0.70),
        ({80,}, 1, 0.50),
        ({443,}, 1, 0.50),
        ({8080,}, 1, 0.60),
        ({8443,}, 1, 0.60),
        # WSUS
        ({8530, 8531}, 2, 0.65),
    ],
    HostRole.FILE_SERVER: [
        # NFS
        ({111, 2049}, 2, 0.80),
        # SMB-only file server (445 without DC ports)
        ({445, 139}, 2, 0.40),
        # FTP
        ({21,}, 1, 0.50),
    ],
    HostRole.NETWORK_EQUIPMENT: [
        ({161, 162}, 1, 0.80),          # SNMP
        ({179,}, 1, 0.85),              # BGP
        ({23, 161}, 2, 0.85),           # Telnet + SNMP = classic network device
    ],
    HostRole.PRINTER: [
        ({9100,}, 1, 0.85),             # JetDirect
        ({515,}, 1, 0.75),              # LPD
        ({631,}, 1, 0.70),              # IPP/CUPS
        ({9100, 515, 631}, 2, 0.95),    # Multiple printer ports
    ],
    HostRole.VOIP: [
        ({5060,}, 1, 0.85),             # SIP
        ({5061,}, 1, 0.85),             # SIP TLS
        ({5060, 5061}, 2, 0.95),
        ({4569,}, 1, 0.80),             # IAX2
    ],
    HostRole.HYPERVISOR: [
        ({902,}, 1, 0.80),              # VMware auth daemon
        ({8006,}, 1, 0.80),             # Proxmox
        ({443, 902}, 2, 0.90),          # VMware ESXi
    ],
    HostRole.REMOTE_ACCESS: [
        ({3389,}, 1, 0.30),             # RDP (low confidence alone — many servers have it)
        ({5900,}, 1, 0.40),             # VNC
        ({5901,}, 1, 0.40),             # VNC
    ],
    HostRole.DNS_SERVER: [
        ({53,}, 1, 0.50),               # DNS (low confidence — DCs also have it)
    ],
    HostRole.PROXY: [
        ({3128,}, 1, 0.80),             # Squid
        ({8080,}, 1, 0.40),             # Could be proxy or web
        ({8888,}, 1, 0.50),             # Common proxy port
    ],
    HostRole.MONITORING: [
        ({10050, 10051}, 1, 0.80),      # Zabbix
        ({5666,}, 1, 0.80),             # Nagios NRPE
        ({9090,}, 1, 0.60),             # Prometheus
        ({3000,}, 1, 0.50),             # Grafana
    ],
}

# Product/banner keywords that strongly indicate a role
PRODUCT_KEYWORDS: dict[str, HostRole] = {
    "exchange": HostRole.MAIL_SERVER,
    "postfix": HostRole.MAIL_SERVER,
    "dovecot": HostRole.MAIL_SERVER,
    "sendmail": HostRole.MAIL_SERVER,
    "exim": HostRole.MAIL_SERVER,
    "active directory": HostRole.DOMAIN_CONTROLLER,
    "kerberos": HostRole.DOMAIN_CONTROLLER,
    "mysql": HostRole.DATABASE,
    "mariadb": HostRole.DATABASE,
    "postgresql": HostRole.DATABASE,
    "sql server": HostRole.DATABASE,
    "oracle": HostRole.DATABASE,
    "mongodb": HostRole.DATABASE,
    "redis": HostRole.DATABASE,
    "elasticsearch": HostRole.DATABASE,
    "vmware": HostRole.HYPERVISOR,
    "esxi": HostRole.HYPERVISOR,
    "proxmox": HostRole.HYPERVISOR,
    "asterisk": HostRole.VOIP,
    "freeswitch": HostRole.VOIP,
    "cups": HostRole.PRINTER,
    "jetdirect": HostRole.PRINTER,
    "hp embedded": HostRole.PRINTER,
    "cisco": HostRole.NETWORK_EQUIPMENT,
    "juniper": HostRole.NETWORK_EQUIPMENT,
    "mikrotik": HostRole.NETWORK_EQUIPMENT,
    "routeros": HostRole.NETWORK_EQUIPMENT,
    "apache": HostRole.WEB_SERVER,
    "nginx": HostRole.WEB_SERVER,
    "iis": HostRole.WEB_SERVER,
    "tomcat": HostRole.WEB_SERVER,
    "lighttpd": HostRole.WEB_SERVER,
    "squid": HostRole.PROXY,
}

# Roles that take priority when there's a conflict.
# Higher number = higher priority.
ROLE_PRIORITY: dict[HostRole, int] = {
    HostRole.DOMAIN_CONTROLLER: 100,
    HostRole.MAIL_SERVER: 90,
    HostRole.DATABASE: 80,
    HostRole.HYPERVISOR: 75,
    HostRole.VOIP: 70,
    HostRole.NETWORK_EQUIPMENT: 65,
    HostRole.PRINTER: 60,
    HostRole.MONITORING: 55,
    HostRole.FILE_SERVER: 50,
    HostRole.DNS_SERVER: 40,
    HostRole.PROXY: 35,
    HostRole.WEB_SERVER: 30,
    HostRole.REMOTE_ACCESS: 10,
    HostRole.UNKNOWN: 0,
}


def classify_host(host: Host) -> ClassificationResult:
    """Classify a host's role based on its open ports and service banners.

    Uses a scoring system:
    1. Check port patterns against rules
    2. Check service product/banner keywords
    3. Pick highest-scoring role as primary
    4. Remaining matches become secondary roles
    """
    open_ports = host.open_tcp_ports
    if not open_ports:
        return ClassificationResult(
            role=HostRole.UNKNOWN,
            confidence=0.0,
            reasons=["No open TCP ports detected"],
            secondary_roles=[],
        )

    # Score each role
    scores: dict[HostRole, float] = {}
    reasons: dict[HostRole, list[str]] = {}

    # Phase 1: Port pattern matching
    for role, rules in ROLE_RULES.items():
        for indicator_ports, min_matches, confidence in rules:
            matched = open_ports & indicator_ports
            if len(matched) >= min_matches:
                port_list = ",".join(str(p) for p in sorted(matched))
                current = scores.get(role, 0.0)
                if confidence > current:
                    scores[role] = confidence
                    reasons[role] = [f"ports {port_list}"]

    # Phase 2: Product/banner keyword matching
    for service in host.services:
        if service.state != "open":
            continue
        text = _service_text(service)
        if not text:
            continue
        for keyword, role in PRODUCT_KEYWORDS.items():
            if keyword in text:
                boost = 0.15
                current = scores.get(role, 0.0)
                new_score = min(current + boost, 0.99)
                if new_score > current:
                    scores[role] = new_score
                    if role not in reasons:
                        reasons[role] = []
                    reasons[role].append(f"product '{keyword}' on port {service.port}")

    # Phase 3: Suppress low-confidence roles that conflict with high-confidence ones
    # e.g., DC always has SMB (445) — don't also classify as file_server
    if HostRole.DOMAIN_CONTROLLER in scores and scores[HostRole.DOMAIN_CONTROLLER] >= 0.80:
        # DC has DNS, SMB, web (for ADCS etc.) — suppress these
        for suppress in (HostRole.FILE_SERVER, HostRole.DNS_SERVER, HostRole.WEB_SERVER, HostRole.REMOTE_ACCESS):
            if suppress in scores and scores[suppress] < scores[HostRole.DOMAIN_CONTROLLER]:
                del scores[suppress]
                reasons.pop(suppress, None)

    if HostRole.MAIL_SERVER in scores and scores[HostRole.MAIL_SERVER] >= 0.70:
        # Mail servers often have web UI
        for suppress in (HostRole.WEB_SERVER, HostRole.REMOTE_ACCESS):
            if suppress in scores and scores[suppress] < scores[HostRole.MAIL_SERVER]:
                del scores[suppress]
                reasons.pop(suppress, None)

    if HostRole.HYPERVISOR in scores and scores[HostRole.HYPERVISOR] >= 0.80:
        for suppress in (HostRole.WEB_SERVER, HostRole.REMOTE_ACCESS):
            if suppress in scores and scores[suppress] < scores[HostRole.HYPERVISOR]:
                del scores[suppress]
                reasons.pop(suppress, None)

    if not scores:
        return ClassificationResult(
            role=HostRole.UNKNOWN,
            confidence=0.0,
            reasons=["No matching port patterns"],
            secondary_roles=[],
        )

    # Phase 4: Pick primary role (highest score, then priority)
    sorted_roles = sorted(
        scores.items(),
        key=lambda x: (x[1], ROLE_PRIORITY.get(x[0], 0)),
        reverse=True,
    )

    primary_role, primary_conf = sorted_roles[0]
    secondary = [r for r, _ in sorted_roles[1:]]

    return ClassificationResult(
        role=primary_role,
        confidence=round(primary_conf, 2),
        reasons=reasons.get(primary_role, []),
        secondary_roles=secondary,
    )


def classify_hosts(hosts: list[Host]) -> list[Host]:
    """Classify all hosts in a list and update their role/confidence."""
    for host in hosts:
        result = classify_host(host)
        host.role = result.role
        host.role_confidence = result.confidence
    return hosts


def _service_text(service: Service) -> str:
    """Build searchable text from service info."""
    parts = []
    if service.product:
        parts.append(service.product.lower())
    if service.name:
        parts.append(service.name.lower())
    if service.extra_info:
        parts.append(service.extra_info.lower())
    return " ".join(parts)
