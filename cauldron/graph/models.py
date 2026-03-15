"""Data models for Cauldron graph entities."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class HostRole(str, Enum):
    """Classified role of a network host."""

    DOMAIN_CONTROLLER = "domain_controller"
    WEB_SERVER = "web_server"
    DATABASE = "database"
    MAIL_SERVER = "mail_server"
    FILE_SERVER = "file_server"
    NETWORK_EQUIPMENT = "network_equipment"
    PRINTER = "printer"
    VOIP = "voip"
    REMOTE_ACCESS = "remote_access"
    HYPERVISOR = "hypervisor"
    DNS_SERVER = "dns_server"
    PROXY = "proxy"
    MONITORING = "monitoring"
    SIEM = "siem"
    CI_CD = "ci_cd"
    VPN_GATEWAY = "vpn_gateway"
    BACKUP = "backup"
    UNKNOWN = "unknown"


@dataclass
class TracerouteHop:
    """A single hop in a traceroute."""

    ttl: int
    ip: str | None = None
    hostname: str | None = None
    rtt: float | None = None  # milliseconds


@dataclass
class ScriptResult:
    """Output of an NSE script."""

    script_id: str
    output: str


@dataclass
class Service:
    """A network service running on a port."""

    port: int
    protocol: str = "tcp"  # tcp | udp
    state: str = "open"  # open | filtered | closed
    name: str | None = None  # e.g. "http", "ssh", "smb"
    product: str | None = None  # e.g. "Apache httpd", "OpenSSH"
    version: str | None = None  # e.g. "2.4.49", "7.4"
    extra_info: str | None = None
    banner: str | None = None
    scripts: list[ScriptResult] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        """Human-readable service description."""
        parts = [f"{self.port}/{self.protocol}"]
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        elif self.name:
            parts.append(self.name)
        return " ".join(parts)


@dataclass
class Host:
    """A discovered network host."""

    ip: str
    hostname: str | None = None
    state: str = "up"
    mac: str | None = None
    mac_vendor: str | None = None
    os_name: str | None = None
    os_accuracy: int | None = None
    ttl: int | None = None
    services: list[Service] = field(default_factory=list)
    traceroute: list[TracerouteHop] = field(default_factory=list)

    # Enrichment fields (populated later)
    role: HostRole = HostRole.UNKNOWN
    role_confidence: float = 0.0

    @property
    def open_ports(self) -> list[int]:
        """List of open port numbers."""
        return [s.port for s in self.services if s.state == "open"]

    @property
    def open_tcp_ports(self) -> set[int]:
        """Set of open TCP port numbers."""
        return {s.port for s in self.services if s.state == "open" and s.protocol == "tcp"}


@dataclass
class ScanResult:
    """Complete result of a scan import."""

    hosts: list[Host] = field(default_factory=list)
    scan_source: str | None = None  # IP/name of the scanning machine
    scanner: str = "nmap"  # nmap | masscan
    scanner_version: str | None = None
    scan_args: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None

    @property
    def hosts_up(self) -> list[Host]:
        """Hosts that are up."""
        return [h for h in self.hosts if h.state == "up"]

    @property
    def total_services(self) -> int:
        """Total number of open services across all hosts."""
        return sum(len(h.services) for h in self.hosts_up)
