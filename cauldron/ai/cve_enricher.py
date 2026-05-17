"""CVE enrichment via NVD API.

Queries the National Vulnerability Database for known CVEs matching
service CPE identifiers or product+version pairs found during scanning.

Strategy (in order of accuracy):
1. CPE-based query via virtualMatchString (precise, uses nmap's CPE output)
2. Fallback CPE mapping for known products without nmap CPE
3. Keyword search as last resort (with version validation)

Features:
- Local JSON file cache to avoid repeated API calls
- Rate limiting (NVD: 5 req/30s without key, 50 req/30s with key)
- CVSS v4.0/v3.1/v3.0/v2 score extraction
- Version validation against CVE configurations
- Filters disputed/rejected CVEs
"""

from __future__ import annotations

import http.client
import json
import logging
import re
import threading
import time
import urllib.request
import urllib.error
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cauldron.config import settings

logger = logging.getLogger(__name__)


class NvdTransientError(RuntimeError):
    """Raised when NVD is unreachable after all retries (network errors,
    5xx responses, malformed JSON).

    The whole point of having a dedicated exception rather than returning
    ``[]`` is to separate "NVD definitively told us zero CVEs" from "we
    never got an authoritative answer". The first is a cacheable fact;
    the second is a temporary hole that must not poison the cache for
    the next seven days.
    """


# NVD API base URL
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Retry budget for a single NVD request. Six attempts with exponential
# backoff gives the largest responses (the ~19 MB
# ``cpe:/o:linux:linux_kernel:*`` payload is the canonical worst case)
# a realistic chance of completing — three retries proved insufficient
# on flaky home connections, where IncompleteRead trips multiple times
# in a row and the operator's host-OS enrichment silently produced
# zero edges. ``_execute_nvd_query`` enforces this for every retryable
# class (IncompleteRead, transient HTTP, network / OS / JSON errors).
_NVD_RETRY_BUDGET = 6

# Socket timeout per attempt. Stretched from the original 30 s so the
# multi-megabyte OS-CPE responses get the bandwidth headroom to finish
# in one go on modest connections — a 19 MB body at 1.5 Mbps barely
# clears the wire in 30 s before the timer trips.
_NVD_REQUEST_TIMEOUT = 90

# EPSS (Exploit Prediction Scoring System) API. FIRST.org publishes a
# per-CVE 0.0-1.0 probability of in-the-wild exploitation in the next 30
# days. Complements has_exploit (binary PoC existence) and CISA KEV
# (retrospective "was used") with a forward-looking threat-intel signal.
# Free, no auth, batch query via comma-separated ``cve=A,B,C``.
EPSS_API_BASE = "https://api.first.org/data/v1/epss"

# How many CVEs to pack per EPSS request. FIRST.org's URL-length ceiling
# handles several hundred, but batches of 100 keep URLs readable and
# progress granular for large scans.
_EPSS_BATCH_SIZE = 100

# Strict CVE-ID shape. FIRST.org's URL is a comma-separated ``cve=`` list,
# no quoting — so a malformed id in the graph (left by a buggy enricher,
# stale data, or a manual Cypher INSERT) could break the URL or cause
# spurious 400s. Match only the official MITRE syntax client-side.
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Cache location
CACHE_DIR = Path.home() / ".cauldron"
CACHE_FILE = CACHE_DIR / "cve_cache.json"
# EPSS cache: scores update daily on FIRST.org so a 24h TTL matches the
# upstream refresh cadence without pointlessly re-fetching on every boil.
EPSS_CACHE_FILE = CACHE_DIR / "epss_cache.json"

# Rate limiting: track last request time. Protected by ``_rate_limit_lock``
# because the AI analyzer calls NVD concurrently from a ThreadPoolExecutor
# during Phase 1 (AI CPE extraction → NVD lookup). Without a lock, parallel
# threads read the same ``_last_request_time``, each sleep the same delta,
# and the burst briefly exceeds NVD's RPS budget.
_last_request_time: float = 0.0
_rate_limit_lock = threading.Lock()

# Fallback: nmap product name -> CPE "vendor:product" for services without
# nmap-provided CPE. Keys are matched lowercased, exact first then prefix —
# so "VMware ESXi Server httpd" (with nmap's service suffix) resolves to
# "vmware:esxi" via the "vmware esxi" prefix key.
PRODUCT_CPE_MAP: dict[str, str] = {
    # --- SSH ---
    "openssh": "openbsd:openssh",
    "dropbear sshd": "matt_johnston:dropbear_ssh",
    "libssh": "libssh:libssh",
    # --- Web servers ---
    "apache httpd": "apache:http_server",
    "nginx": "f5:nginx",
    "microsoft iis httpd": "microsoft:internet_information_services",
    "lighttpd": "lighttpd:lighttpd",
    "apache tomcat": "apache:tomcat",
    "apache coyote": "apache:tomcat",
    "cherokee httpd": "cherokee-project:cherokee",
    # --- Databases ---
    "mysql": "oracle:mysql",
    "postgresql": "postgresql:postgresql",
    "mariadb": "mariadb:mariadb",
    "redis": "redis:redis",
    "mongodb": "mongodb:mongodb",
    "memcached": "memcached:memcached",
    "microsoft sql server": "microsoft:sql_server",
    # --- FTP ---
    "vsftpd": "vsftpd_project:vsftpd",
    "proftpd": "proftpd:proftpd",
    "pure-ftpd": "pureftpd:pure-ftpd",
    "filezilla ftpd": "filezilla-project:filezilla_server",
    # --- Mail ---
    "postfix smtpd": "postfix:postfix",
    "exim smtpd": "exim:exim",
    "dovecot": "dovecot:dovecot",
    "sendmail": "sendmail:sendmail",
    "microsoft exchange smtpd": "microsoft:exchange_server",
    "microsoft exchange server": "microsoft:exchange_server",
    "microsoft exchange": "microsoft:exchange_server",
    # --- DNS ---
    "isc bind": "isc:bind",
    "dnsmasq": "thekelleys:dnsmasq",
    # --- SMB/File ---
    "samba smbd": "samba:samba",
    # --- Proxy / edge ---
    "squid http proxy": "squid-cache:squid",
    "haproxy": "haproxy:haproxy",
    # --- Misc services ---
    "openvpn": "openvpn:openvpn",
    "openldap": "openldap:openldap",
    "elasticsearch": "elastic:elasticsearch",
    "jenkins": "jenkins:jenkins",
    "grafana": "grafana:grafana",
    # --- Virtualization ---
    "vmware esxi": "vmware:esxi",
    "vmware esxi soap api": "vmware:esxi",
    "vmware vcenter server": "vmware:vcenter_server",
    "vmware vcenter": "vmware:vcenter_server",
    # --- Messaging / middleware ---
    "apache activemq": "apache:activemq",
    # --- Collaboration ---
    "atlassian confluence": "atlassian:confluence_server",
    "atlassian jira": "atlassian:jira_server",
    # --- Network gear ---
    "mikrotik routeros": "mikrotik:routeros",
    "routeros": "mikrotik:routeros",
    # --- Edge / VPN ---
    "citrix netscaler": "citrix:netscaler_application_delivery_controller",
    "fortinet fortios": "fortinet:fortios",
    "fortinet fortigate": "fortinet:fortios",
    "palo alto pan-os": "paloaltonetworks:pan-os",
}


@dataclass
class CVEInfo:
    """Information about a single CVE."""

    cve_id: str
    cvss: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    description: str = ""
    has_exploit: bool = False
    exploit_url: str | None = None
    # ``+``-joined set of channels that confirmed a public exploit exists
    # for this CVE: ``"nvd"`` (NVD-tagged ``Exploit`` reference or known
    # PoC-host URL pattern), ``"exploitdb"`` (entry in the ExploitDB
    # canonical index), ``"metasploit"`` (Metasploit-Framework module).
    # An empty string when ``has_exploit`` is False — UI uses this to
    # render per-source chips (``EXPLOIT [NVD][MSF]``) and the operator
    # can tell at a glance which channels validated the finding.
    exploit_sources: str = ""
    epss: float | None = None
    cwe_ids: list[str] = field(default_factory=list)
    published: str | None = None  # ISO date string from NVD
    # CISA Known Exploited Vulnerabilities catalog — True when CISA lists
    # the CVE as actively exploited in the wild (stronger signal than
    # has_exploit, which only means a PoC exists somewhere).
    in_cisa_kev: bool = False
    cisa_kev_added: str | None = None  # ISO date CISA added it
    # Whether the CPE this CVE matched on had a pinned version (either
    # the CPE itself or a service_version_override threaded through the
    # wildcard-retry path). Set by ``_query_nvd_cpe`` after a query
    # returns; ``_upsert_vulnerability`` stores the inverse on the
    # HAS_VULN edge as ``r.version_unconfirmed``.
    #
    # The point: a service can lack a primary version (compound banner
    # at :443 makes ``s.version=None``) yet still have a CVE attached
    # via a sub-product CPE with a known version (mod_ssl/2.8.4 from
    # the same banner). The old service-level ``version_unconfirmed``
    # flagged those edges as uncertain when they were actually
    # version-anchored. Per-edge flag lets the API/UI report the truth.
    matched_version_pinned: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> CVEInfo:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class EnrichmentResult:
    """Result of enriching a single service."""

    product: str
    version: str
    cves: list[CVEInfo] = field(default_factory=list)
    from_cache: bool = False
    error: str | None = None


class CVECache:
    """Simple JSON file cache for CVE lookups with TTL support."""

    DEFAULT_TTL = 7 * 24 * 3600  # 7 days in seconds

    def __init__(self, cache_file: Path = CACHE_FILE, ttl: int | None = None):
        self._file = cache_file
        self._ttl = ttl if ttl is not None else self.DEFAULT_TTL
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if self._file.exists():
            try:
                raw = json.loads(self._file.read_text(encoding="utf-8"))
                for key, value in raw.items():
                    if isinstance(value, list):
                        self._data[key] = {"cves": value, "_cached_at": 0}
                    elif isinstance(value, dict):
                        self._data[key] = value
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def _save(self) -> None:
        self._file.parent.mkdir(parents=True, exist_ok=True)
        self._file.write_text(json.dumps(self._data, indent=2), encoding="utf-8")

    def get(self, key: str) -> list[CVEInfo] | None:
        """Get cached CVEs for a key. Returns None if expired."""
        entry = self._data.get(key)
        if entry is None:
            return None
        cached_at = entry.get("_cached_at", 0)
        if self._ttl > 0 and time.time() - cached_at > self._ttl:
            del self._data[key]
            return None
        return [CVEInfo.from_dict(d) for d in entry.get("cves", [])]

    def put(self, key: str, cves: list[CVEInfo]) -> None:
        """Cache CVEs for a key with timestamp."""
        self._data[key] = {
            "cves": [c.to_dict() for c in cves],
            "_cached_at": time.time(),
        }
        self._save()

    @property
    def size(self) -> int:
        return len(self._data)


class EPSSCache:
    """JSON cache for per-CVE EPSS scores. 24h TTL matches FIRST.org's
    daily refresh cadence — no point re-fetching more often than the
    data actually changes.
    """

    DEFAULT_TTL = 24 * 3600  # 24 hours

    def __init__(self, cache_file: Path | None = None, ttl: int | None = None):
        # Read EPSS_CACHE_FILE at call time rather than as a default-arg
        # sentinel so monkeypatch-style redirection in tests works (the
        # default-arg binding would otherwise freeze the original path at
        # class-definition time).
        self._file = cache_file if cache_file is not None else EPSS_CACHE_FILE
        self._ttl = ttl if ttl is not None else self.DEFAULT_TTL
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if self._file.exists():
            try:
                self._data = json.loads(self._file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def _save(self) -> None:
        self._file.parent.mkdir(parents=True, exist_ok=True)
        self._file.write_text(json.dumps(self._data, indent=2), encoding="utf-8")

    def get(self, cve_id: str) -> float | None:
        """Return cached EPSS score for cve_id, or None if missing/expired."""
        entry = self._data.get(cve_id)
        if entry is None:
            return None
        if self._ttl > 0 and time.time() - entry.get("_cached_at", 0) > self._ttl:
            del self._data[cve_id]
            return None
        return entry.get("epss")

    def put_batch(self, scores: dict[str, float]) -> None:
        """Cache a batch of CVE -> EPSS scores with a single save."""
        now = time.time()
        for cve_id, epss in scores.items():
            self._data[cve_id] = {"epss": epss, "_cached_at": now}
        self._save()


def _rate_limit() -> None:
    """Enforce NVD API rate limits. Thread-safe (see ``_rate_limit_lock``)."""
    global _last_request_time
    delay = 0.7 if settings.nvd_api_key else 6.5
    with _rate_limit_lock:
        elapsed = time.time() - _last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)
        _last_request_time = time.time()


# --- CPE helpers ---

# Nmap CPE vendor:product → NVD CPE vendor:product corrections
# Nmap uses outdated or non-standard vendor names for some products
_CPE_VENDOR_CORRECTIONS: dict[str, str] = {
    "igor_sysoev:nginx": "f5:nginx",
    "microsoft:internet_information_server": "microsoft:internet_information_services",
}

# OS CPE products worth querying NVD for (have specific, useful CVEs).
# NVD registers these as ``o:`` (operating system) type — application-typed
# queries against them return zero matches. Two groups:
#
# - **Appliance OSes** (ESXi, IOS, FortiOS, PAN-OS, …): the product name
#   is generic and the version slot carries the actual release. We
#   require a concrete version on the queried CPE — a wildcard query
#   against ``vmware:esxi:*`` would dump every ESXi CVE ever filed.
# - **Microsoft Windows family** (windows_7, windows_server_2012, …):
#   the product name already encodes the major OS version, and the CPE
#   2.2 URIs nmap emits for them have an empty version slot by design
#   (the SP marker lives in ``update``, the edition in ``edition``). A
#   wildcard query against ``microsoft:windows_7:*`` returns the bounded
#   set of Win 7 CVEs — which is what we want for OS-level RCE detection
#   (MS17-010, BlueKeep). The bare ``microsoft:windows`` form (no
#   major-version product) is deliberately excluded — nmap attaches it
#   to every Windows service and a query against it would flood with
#   every Windows CVE NVD has ever recorded.
_OS_CPE_PRODUCTS: set[str] = {
    # Appliance OSes — strict version requirement.
    "vmware:esxi",
    "cisco:ios",
    "cisco:ios_xe",
    "cisco:nxos",
    "paloaltonetworks:pan-os",
    "fortinet:fortios",
    "juniper:junos",
    "mikrotik:routeros",
    # Linux kernel — host-OS enrichment surfaces kernel privesc CVEs
    # (CVE-2009-2698 sock_sendpage, CVE-2010-3904 RDS, …) that the
    # service-level pipeline can't reach. The version slot here
    # carries the actual kernel release (``2.6``, ``3.10``, ``5.15``),
    # so the appliance-style "concrete version required" rule fits.
    "linux:linux_kernel",
}

# Microsoft Windows family CPEs — product name encodes the major
# version, so wildcard version queries are correct and useful here
# (see ``_OS_CPE_PRODUCTS`` docstring above).
_OS_CPE_WINDOWS_FAMILIES: set[str] = {
    "microsoft:windows_7",
    "microsoft:windows_8",
    "microsoft:windows_8.1",
    "microsoft:windows_10",
    "microsoft:windows_11",
    "microsoft:windows_xp",
    "microsoft:windows_vista",
    "microsoft:windows_nt",
    "microsoft:windows_2000",
    "microsoft:windows_server_2003",
    "microsoft:windows_server_2008",
    "microsoft:windows_server_2012",
    "microsoft:windows_server_2016",
    "microsoft:windows_server_2019",
    "microsoft:windows_server_2022",
    # Alternate product names used in older NVD CPE entries.
    "microsoft:windows_2003",
    "microsoft:windows_2008",
    "microsoft:windows_2012",
}

# Regex to extract base version from fuzzy nmap version strings
_VERSION_EXTRACT_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


def _cpe22_to_23(cpe: str) -> str | None:
    """Convert CPE 2.2 URI (cpe:/a:vendor:product:version) to CPE 2.3 format.

    Handles application CPEs (cpe:/a:) and selected OS CPEs (cpe:/o:)
    for high-value targets like ESXi, Cisco IOS, etc.
    Applies vendor corrections for known nmap/NVD mismatches.
    """
    if not cpe.startswith("cpe:/"):
        return None
    parts = cpe[5:].split(":")
    if len(parts) < 3:
        return None
    part_type = parts[0]  # a, o, h
    vendor = parts[1] if len(parts) > 1 else "*"
    product = parts[2] if len(parts) > 2 else "*"
    version = parts[3] if len(parts) > 3 else "*"

    if part_type == "a":
        # Apply vendor corrections
        vp_key = f"{vendor}:{product}".lower()
        if vp_key in _CPE_VENDOR_CORRECTIONS:
            corrected = _CPE_VENDOR_CORRECTIONS[vp_key]
            vendor, product = corrected.split(":", 1)
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

    if part_type == "o":
        vendor_l = vendor.lower()
        product_l = product.lower()
        vp_key = f"{vendor_l}:{product_l}"
        # Appliance OSes require a concrete version — a wildcard query
        # against ``vmware:esxi:*`` returns every ESXi CVE ever filed.
        if vp_key in _OS_CPE_PRODUCTS and version != "*" and version != "":
            return f"cpe:2.3:o:{vendor_l}:{product_l}:{version}:*:*:*:*:*:*:*"
        # Microsoft Windows family CPEs — the product name encodes the
        # major version (windows_7, windows_server_2012, …), so an
        # empty/wildcard version slot is the normal shape (the SP and
        # edition live in update/edition slots that NVD wildcards in
        # most match expressions anyway). Map an empty slot to ``*``.
        if vp_key in _OS_CPE_WINDOWS_FAMILIES:
            cpe_version = version if version else "*"
            return f"cpe:2.3:o:{vendor_l}:{product_l}:{cpe_version}:*:*:*:*:*:*:*"

    return None


def _with_version(cpe23: str | None, version: str | None) -> str | None:
    """Upgrade a versionless CPE 2.3 with a known service version.

    nmap routinely emits ``<service version="3.0.20-Debian">`` alongside a
    versionless ``<cpe>cpe:/a:samba:samba</cpe>`` — the version slot
    isn't filled in the CPE tag even when nmap clearly extracted it.
    Cauldron passing the versionless CPE through to NVD then drops
    range-bounded CVEs pinned to specific versions (CVE-2007-2447 is
    filed as ``cpe:2.3:a:samba:samba:3.0.0`` ... ``:3.0.20``; the
    versionless path can't confirm 3.0.20 is in the set).

    This helper merges the service version into the CPE when:
      - the CPE itself has a wildcard version slot (``parts[5] == "*"``),
        i.e. we're not overriding an explicit nmap pin
      - ``version`` parses to a concrete pin via ``_extract_version`` --
        ``"3.X - 4.X"`` returns ``"*"`` and is left alone (a real range,
        not a missing pin), while ``"3.0.20-Debian"`` parses to
        ``"3.0.20"`` and lands in the CPE.

    Returns the upgraded CPE on a merge, or the original unchanged for
    any of: empty cpe23, no service version, unparseable version,
    or a CPE that already has a pinned version.
    """
    if not cpe23 or not version:
        return cpe23
    parts = cpe23.split(":")
    if len(parts) < 6 or parts[5] != "*":
        return cpe23   # already pinned, don't override
    pinned = _extract_version(version)
    if not pinned or pinned == "*":
        return cpe23   # version string didn't yield a clean pin
    parts[5] = pinned
    return ":".join(parts)


def _build_cpe23(vendor: str, product: str, version: str = "*") -> str:
    """Build a CPE 2.3 string from components.

    Picks the CPE part type (application ``a`` vs operating system ``o``) based
    on whether the vendor:product is in the OS-registered sets. Products like
    ESXi, MikroTik RouterOS, PAN-OS, FortiOS, Cisco IOS — and every member of
    the Microsoft Windows family — are registered as ``o:`` in NVD;
    application-typed queries against them return zero matches.
    """
    vp_key = f"{vendor}:{product}".lower()
    is_os = vp_key in _OS_CPE_PRODUCTS or vp_key in _OS_CPE_WINDOWS_FAMILIES
    part_type = "o" if is_os else "a"
    return f"cpe:2.3:{part_type}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _relax_cpe_version(cpe23: str) -> str | None:
    """Rebuild a CPE 2.3 string with a wildcard version.

    Used as a fallback when a specific-version query returns zero CVEs —
    some vendors (notably VMware and Cisco) register CVEs against a major
    version only (e.g. ``vcenter_server:7.0``) while nmap reports patch
    levels (``7.0.3``) that never match literally.
    """
    parts = cpe23.split(":")
    if len(parts) < 13 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    if parts[5] == "*":
        return None
    parts[5] = "*"
    return ":".join(parts)


def _extract_version(version_str: str | None) -> str:
    """Extract a clean version number from fuzzy nmap version strings.

    Examples:
        "9.6.0 or later" → "9.6.0"
        "2-4" → "*" (range, not parseable)
        "8.0.3" → "8.0.3"
        None → "*"
    """
    if not version_str:
        return "*"
    m = _VERSION_EXTRACT_RE.search(version_str)
    if m:
        return m.group(1)
    return "*"


def _get_cpe_for_service(cpe_list: list[str], product: str | None, version: str | None) -> str | None:
    """Get best CPE 2.3 string for a service.

    Priority:
    1. Application/OS CPE from nmap (with vendor corrections), upgraded
       with ``service.version`` when nmap emitted a versionless CPE.
    2. Fallback mapping from PRODUCT_CPE_MAP.
    """
    # Try nmap's CPE output first. When nmap emitted a versionless CPE
    # (e.g. ``cpe:/a:samba:samba`` on a service whose version attribute
    # carries ``3.0.20-Debian``), merge the service version in so NVD
    # queries can hit version-pinned CVEs (CVE-2007-2447 Samba usermap).
    # ``_with_version`` is a no-op when the CPE already has a pin or
    # when ``version`` doesn't parse to a clean value.
    for cpe in cpe_list:
        cpe23 = _cpe22_to_23(cpe)
        if cpe23:
            return _with_version(cpe23, version)

    # Fallback: use product name mapping. Try exact match first, then
    # prefix-based match — nmap frequently appends a service suffix to the
    # canonical product name, e.g. "VMware ESXi Server httpd" for port 443
    # or "VMware vCenter Server SOAP API" — we still want to map to the base
    # vendor:product CPE.
    if product:
        product_lower = product.lower().strip()
        vendor_product = PRODUCT_CPE_MAP.get(product_lower)
        if vendor_product is None:
            for key in PRODUCT_CPE_MAP:
                if product_lower.startswith(key + " ") or product_lower == key:
                    vendor_product = PRODUCT_CPE_MAP[key]
                    break
        if vendor_product:
            vendor, prod = vendor_product.split(":", 1)
            ver = _extract_version(version)
            return _build_cpe23(vendor, prod, ver)

    return None


# --- Banner-token CPE resolver ---
#
# nmap's -sV often emits sub-product info that doesn't make it into the
# structured product/version fields:
#   - compound product string  : "Apache/1.3.20 (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b"
#   - extrainfo attribute      : "(Unix) (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b"
#   - NSE script outputs       : http-server-header echoing the same banner
#
# NVD frequently registers CVEs against the sub-product CPE (mod_ssl:mod_ssl:2.8.4)
# rather than the parent (apache:http_server:1.3.20). To surface those we
# tokenize banner sources into (name, version) pairs and resolve each one to a
# canonical CPE via NVD's CPE Dictionary -- the dictionary IS the lookup, so
# we don't maintain a static name->vendor:product mapping that drifts. Tokens
# that don't correspond to real NVD entries (e.g. "Red-Hat/Linux") self-filter
# by returning zero matches.

NVD_CPE_BASE = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

# (name, "/", version). The name allows letters/digits/underscores/dashes/dots
# but must start with a letter so we don't pick up "1.2.3/4.5.6". A 2-character
# minimum drops single-letter false positives. Version must start with a digit
# so we don't match "foo/bar".
_BANNER_TOKEN_RE = re.compile(r"\b([A-Za-z][\w.-]{1,})/(\d[\w.-]*)")

# Bare version-like substring, used when the service has a known product but
# nmap left the version field empty. NSE scripts often emit the version glued
# to a product alias (irc-info: ``Unreal3.2.8.1``) that neither the slash nor
# the space form catches. Matched substring is paired downstream with the
# known service product; junk extractions (IP addresses, timestamps) self-
# filter via NVD's virtualMatchString returning zero CVEs for fake CPEs.
# Requires at least one dot to drop bare integers (port numbers, counts).
#
# Uses negative lookbehind/lookahead for digits rather than ``\b`` because
# ``\b`` does not match between a letter and a digit (both are "word" chars),
# so ``\b\d+`` against "Unreal3.2.8.1" would skip the leading "3." and capture
# only "2.8.1". ``(?<!\d)\d+...`` skips matches mid-version-string while still
# anchoring at letter-to-digit transitions.
_BARE_VERSION_RE = re.compile(r"(?<!\d)(\d+\.\d+(?:\.\d+){0,3}[a-z]?)(?!\d)")

# Same shape but space-separated: "Drupal 7" from http-generator NSE output,
# "Samba 2.2.1a" from smb-os-discovery, "IIS 7.5" from http-server-header.
# Stricter than the slash form because plain prose is full of "Word number"
# pairs and we don't want to flood the resolver:
#   - name must start with a CAPITAL letter (filters lowercase prose like
#     "running version 1.2.3 of foo")
#   - name must be at least 3 chars (drops "NT 10.0" abbreviations that
#     aren't products on their own; real product names rarely sit at 2)
#   - must be at start-of-string or preceded by whitespace, "(" or "["
#     so we don't pick "PowerShell" out of "FoobarPowerShell 7.4"
#   - version must start with a digit (same logic as the slash regex)
# Tokens that survive the regex but aren't real products (e.g. "Mint 19.1")
# still self-filter via NVD's CPE Dictionary returning zero hits.
_BANNER_TOKEN_SPACE_RE = re.compile(r"(?:^|[\s(\[])([A-Z][\w.-]{2,})\s+(\d[\w.-]*)")

# Session-scoped cache. Key = (name.lower(), version).
# Value = canonical CPE 2.3 string, or "" sentinel meaning "queried, NVD has
# no record" -- both avoid repeat lookups within a single boil --nvd run.
_cpe_resolution_cache: dict[tuple[str, str], str] = {}


def _extract_bare_versions(*sources: str | None) -> list[str]:
    """Pull every version-shaped substring out of free-form text.

    Used when a Service has a known ``product`` but the nmap ``version``
    attribute is empty — NSE script outputs (irc-info, http-generator,
    snmp-info, etc.) often carry the version glued to a product alias
    that ``_BANNER_TOKEN_RE`` / ``_BANNER_TOKEN_SPACE_RE`` cannot split
    (``Unreal3.2.8.1`` has no slash and no space between name and
    version). The caller pairs each extracted version with the already-
    known product and synthesises a CPE candidate ``cpe:2.3:a:*:<product>:
    <version>:*`` for downstream NVD virtualMatchString validation.

    Junk extractions are expected and harmless: IP addresses, dates
    written ``2010.03.17``, and uptime fragments all match the regex
    shape. NVD's virtualMatchString returns zero CVEs for nonsense
    product+version pairs, so the candidates self-filter without us
    needing a "is this a real version" allow-list.

    Returns deduplicated version strings preserving first-seen order.
    """
    out: list[str] = []
    seen: set[str] = set()
    for src in sources:
        if not src:
            continue
        for m in _BARE_VERSION_RE.finditer(src):
            v = m.group(1)
            if v not in seen:
                seen.add(v)
                out.append(v)
    return out


def _extract_banner_tokens(*sources: str | None) -> list[tuple[str, str]]:
    """Find (name, version) pairs in one or more banner-shaped strings.

    Catches two shapes:
      - ``Name/Version`` (compound product banners, http-server-header):
        ``Apache/1.3.20``, ``mod_ssl/2.8.4``, ``OpenSSL/0.9.6b``.
      - ``Name Version`` (NSE script outputs that pretty-print products):
        ``Drupal 7`` from http-generator, ``Samba 2.2.1a`` from
        smb-os-discovery, ``IIS 7.5`` from http-server-header.

    Returns deduplicated pairs preserving first-seen order; dedup is keyed
    on ``(name.lower(), version)`` so the same product spelled differently
    across two sources (or two shapes) resolves once. Junk tokens are not
    filtered here -- ``_resolve_banner_token`` rejects them via the NVD
    dictionary returning zero hits.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for src in sources:
        if not src:
            continue
        for regex in (_BANNER_TOKEN_RE, _BANNER_TOKEN_SPACE_RE):
            for m in regex.finditer(src):
                name, version = m.group(1), m.group(2)
                key = (name.lower(), version)
                if key not in seen:
                    seen.add(key)
                    out.append((name, version))
    return out


_PROBE_TRANSIENT = object()  # sentinel: probe couldn't reach NVD, caller should not cache


def _probe_nvd_cpe_dict(name: str, version: str) -> str | None | object:
    """Single shot at NVD's CPE Dictionary for a (name, version) pair.

    Returns:
      - Vendor-wildcarded CPE string when NVD has at least one app entry
        matching ``cpe:2.3:a:*:<name>:<version>:*``.
      - ``None`` when NVD definitively says "no such record" (zero hits or
        non-429 HTTP error).
      - ``_PROBE_TRANSIENT`` sentinel on network errors. Caller must not
        cache a transient as a real "not-found".

    Honors the global ``_rate_limit()`` and the 6 s / 12 s 429 backoff.
    """
    cpe_match = f"cpe:2.3:a:*:{name.lower()}:{version}:*:*:*:*:*:*:*"
    url = f"{NVD_CPE_BASE}?cpeMatchString={urllib.request.quote(cpe_match)}&resultsPerPage=20"

    headers = {"User-Agent": "Cauldron/0.1.0"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    products: list[dict] | None = None
    for attempt in range(3):
        _rate_limit()
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                products = json.loads(resp.read()).get("products", [])
            break
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 2:
                backoff = 6.0 * (2 ** attempt)  # 6 s, 12 s -- NVD's recommended sleep
                logger.info(
                    "NVD 429 on CPE resolve %s/%s, sleeping %.0fs (attempt %d/3)",
                    name, version, backoff, attempt + 1,
                )
                time.sleep(backoff)
                continue
            logger.info(
                "NVD CPE resolve %s/%s returned HTTP %d -- caching as not-found",
                name, version, e.code,
            )
            return None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            # Transient -- don't cache. Next caller may succeed.
            logger.warning("NVD CPE resolve transient failure for %s/%s: %s", name, version, e)
            return _PROBE_TRANSIENT

    if products is None:
        return _PROBE_TRANSIENT

    # Keep only application-typed CPEs (we tokenize app banners).
    app_cpes = [p.get("cpe", {}).get("cpeName", "") for p in products]
    app_cpes = [m for m in app_cpes if m and len(m.split(":")) >= 13 and m.split(":")[2] == "a"]

    if not app_cpes:
        return None

    # Return the vendor-wildcarded form, not the canonical vendor:product.
    # NVD's CPE Dictionary canonicalizes some products under one vendor
    # (e.g. mod_ssl is filed as modssl:mod_ssl, nginx as nginx:nginx) but
    # the historic CVE records reference different vendor strings for the
    # same product (mod_ssl:mod_ssl for the old Slapper CVE-2002-0082;
    # f5:nginx for every real nginx CVE). A canonical-form CVE query
    # silently misses those.
    #
    # cpeMatchString returning non-empty above is enough proof that NVD
    # has at least one real entry for this product+version; the wildcard
    # vendor form lets the downstream _query_nvd_cpe sweep up every CVE
    # filed under any vendor string for the same product, including
    # historic ones the dictionary never backfilled.
    return f"cpe:2.3:a:*:{name.lower()}:{version}:*:*:*:*:*:*:*"


def _resolve_banner_token(name: str, version: str) -> str | None:
    """Look up the canonical NVD CPE 2.3 for a (name, version) banner token.

    Asks NVD's CPE Dictionary with version pinned and vendor wildcarded:
    ``cpe:2.3:a:*:<name>:<version>:*:*:*:*:*:*:*``. NVD returns the real
    canonical CPE(s) matching that shape. When NVD has no record (the token
    was garbage like 'Red-Hat/Linux'), we cache a sentinel and skip retries.

    Major-only version retry: NSE scripts like http-generator emit bare
    major versions ("Drupal 7" instead of "Drupal 7.0"). NVD's CPE
    Dictionary records versions at major.minor minimum, so the exact
    ``drupal:7`` probe returns zero hits even though ``drupal:7.0`` has
    16 entries (and the downstream CVE search at ``drupal:7.0`` lands 93
    CVEs including CVE-2018-7600 Drupalgeddon2). When the banner version
    is purely a digit and the exact probe missed, we retry once with
    ``.0`` suffixed -- the most conservative possible upgrade. The
    upgraded CPE goes back to the caller (``cpe:...:drupal:7.0:*``) so
    downstream NVD CVE search uses the form NVD actually understands.

    Returns the canonical CPE string, or None when no match exists.

    Honors the existing ``_rate_limit()`` (0.7 s/req with key, 6.5 s without).
    On HTTP 429 we back off 6 s / 12 s and retry up to twice -- NVD's "soft"
    throttling lives outside the documented 50/30 s window, so the resolver
    stays safe even when the global rate-limit constant is calibrated to
    the technical ceiling.
    """
    key = (name.lower(), version)
    cached = _cpe_resolution_cache.get(key)
    if cached is not None:
        return cached or None

    # Probe order: exact banner version first, then major.0 fallback only
    # when the banner gave us a bare major (digit-only with no dot).
    versions_to_try = [version]
    if version.isdigit():
        versions_to_try.append(version + ".0")

    saw_transient = False
    for probe_version in versions_to_try:
        result = _probe_nvd_cpe_dict(name, probe_version)
        if isinstance(result, str):
            _cpe_resolution_cache[key] = result
            return result
        if result is _PROBE_TRANSIENT:
            saw_transient = True
            break  # don't burn the .0 retry budget on a flaky network

    if saw_transient:
        # Don't cache -- next caller may succeed.
        return None

    _cpe_resolution_cache[key] = ""
    return None


def _build_cpe_candidates(
    cpe_list: list[str],
    product: str | None,
    version: str | None,
    extra_info: str | None = None,
    script_outputs: list[str] | None = None,
) -> list[str]:
    """All CPE 2.3 candidates for a service, deduplicated.

    Combines three sources, in priority order:
      1. The primary CPE from ``_get_cpe_for_service`` (nmap-emitted or
         PRODUCT_CPE_MAP fallback).
      2. Any other nmap-emitted CPEs from the same service, converted to 2.3.
      3. Sub-product tokens extracted from ``extra_info``, the ``product``
         field when it carries a compound banner, and NSE script outputs --
         each resolved through NVD's CPE Dictionary.

    (1) and (2) are offline / deterministic. (3) may make NVD calls
    (cached session-wide). Junk tokens self-filter via NVD returning zero
    hits, so we don't need a static name -> vendor:product map.
    """
    candidates: list[str] = []
    seen: set[str] = set()

    def _add(cpe: str | None) -> None:
        if cpe and cpe not in seen:
            seen.add(cpe)
            candidates.append(cpe)

    primary = _get_cpe_for_service(cpe_list, product, version)
    _add(primary)

    for raw in cpe_list:
        # Same versionless-CPE upgrade as ``_get_cpe_for_service`` applies
        # to the primary: when nmap emitted a CPE without a version slot
        # but the service has a known version, merge them so the
        # candidate query can find version-pinned CVEs.
        _add(_with_version(_cpe22_to_23(raw), version))

    # Compound-product detection: only tokenize the product field if it
    # contains multiple Name/Version patterns (i.e. nmap dumped the whole
    # banner there). For structured products like "Apache httpd" the regex
    # won't match anyway, so this is just an explicit skip-the-common-case.
    sources: list[str | None] = [extra_info]
    if product and sum(1 for _ in _BANNER_TOKEN_RE.finditer(product)) >= 2:
        sources.append(product)
    if script_outputs:
        sources.extend(script_outputs)

    for name, ver in _extract_banner_tokens(*sources):
        _add(_resolve_banner_token(name, ver))

    # Versionless service with a known single-word product: NSE scripts may
    # report the version glued to a product alias (irc-info: ``Unreal3.2.8.1``
    # for UnrealIRCd) that the slash and space banner regexes cannot split.
    # Pair every version-shaped token from script outputs and extra_info with
    # the known service product and synthesise the CPE directly — no CPE
    # Dictionary probe because the dictionary is curated and incomplete:
    # CVE-2010-2075 references ``unrealircd:unrealircd:3.2.8.1`` in its config
    # tree but that exact CPE has zero entries in the dictionary, so the
    # probe would reject the only candidate that actually finds the CVE.
    # NVD's virtualMatchString is the validator downstream.
    #
    # Multi-word products ("Apache httpd", "Postfix smtpd") already resolve
    # through the PRODUCT_CPE_MAP primary path and don't need this fallback;
    # skipping them avoids polluting the candidate list with malformed CPEs
    # ("apache httpd" is not a valid CPE product slot).
    if (
        product and not version and script_outputs
        and " " not in product.strip()
    ):
        product_slot = product.strip().lower()
        for v in _extract_bare_versions(extra_info, *script_outputs):
            _add(f"cpe:2.3:a:*:{product_slot}:{v}:*:*:*:*:*:*:*")

    return candidates


# --- Pentester relevance filter ---

# CWE IDs that are high-impact for red team / pentesting
# These represent vulnerability classes that give real engagement impact
PENTESTER_CWE_IDS: set[str] = {
    # Remote Code Execution / Command Injection
    "CWE-78",   # OS Command Injection
    "CWE-94",   # Code Injection
    "CWE-95",   # Eval Injection
    "CWE-96",   # Static Code Injection
    "CWE-917",  # Expression Language Injection
    # Deserialization
    "CWE-502",  # Deserialization of Untrusted Data
    # File operations
    "CWE-22",   # Path Traversal
    "CWE-434",  # Unrestricted Upload of File with Dangerous Type
    "CWE-59",   # Improper Link Resolution (symlink attacks)
    # Authentication / Authorization bypass
    "CWE-287",  # Improper Authentication
    "CWE-288",  # Authentication Bypass Using Alternate Path
    "CWE-290",  # Authentication Bypass by Spoofing
    "CWE-306",  # Missing Authentication for Critical Function
    "CWE-862",  # Missing Authorization
    "CWE-863",  # Incorrect Authorization
    "CWE-269",  # Improper Privilege Management
    # Privilege Escalation
    "CWE-250",  # Execution with Unnecessary Privileges
    "CWE-274",  # Improper Handling of Insufficient Privileges
    # Injection (SQL, LDAP, etc.)
    "CWE-89",   # SQL Injection
    "CWE-90",   # LDAP Injection
    "CWE-91",   # XML Injection
    "CWE-611",  # XXE
    "CWE-918",  # SSRF
    # Memory corruption (useful for known exploits)
    # NOTE: CWE-119 (generic buffer overflow) excluded — NVD assigns it too broadly
    "CWE-120",  # Classic Buffer Overflow
    "CWE-122",  # Heap Buffer Overflow
    "CWE-416",  # Use After Free
    "CWE-787",  # Out-of-bounds Write
    # Credentials / secrets
    "CWE-798",  # Hard-coded Credentials
    "CWE-259",  # Hard-coded Password
    "CWE-321",  # Hard-coded Cryptographic Key
    "CWE-312",  # Cleartext Storage of Sensitive Info
}

# Keywords in CVE description that indicate pentester-relevant impact
# Checked case-insensitively against the description text
_PENTESTER_KEYWORDS: list[str] = [
    "remote code execution",
    "arbitrary code execution",
    "command injection",
    "command execution",
    "arbitrary command",
    "code injection",
    "execute arbitrary",
    "unauthenticated",
    "authentication bypass",
    "auth bypass",
    "privilege escalation",
    "gain root",
    "gain admin",
    "gain elevated",
    "deserialization",
    "deserializ",
    "arbitrary file upload",
    "unrestricted upload",
    "file inclusion",
    "directory traversal",
    "path traversal",
    "arbitrary file read",
    "arbitrary file write",
    "sql injection",
    "ldap injection",
    "ssrf",
    "server-side request forgery",
    "xxe",
    "xml external entity",
    "jndi",
    "log4shell",
    "log4j",
    "buffer overflow",
    "heap overflow",
    "stack overflow",
    "use-after-free",
    "hard-coded credential",
    "hardcoded credential",
    "default credential",
    "backdoor",
    "man-in-the-middle",
    "machine-in-the-middle",
    "impersonat",
]


def _is_pentester_relevant(cve: CVEInfo) -> bool:
    """Check if a CVE is relevant for red team / pentesting.

    Keeps CVEs that provide real engagement impact:
    - Has known public exploit → always keep
    - CWE matches pentester-relevant categories → keep
    - CVSS vector indicates network RCE pattern → keep
    - Description contains pentester keywords → keep
    - CVSS >= 9.0 (critical) → keep as safety net
    """
    # 1. Known exploit — always relevant
    if cve.has_exploit:
        return True

    # 2. CWE-based check (require CVSS >= 6.0 to filter trivial matches)
    if cve.cwe_ids and PENTESTER_CWE_IDS.intersection(cve.cwe_ids):
        if cve.cvss is None or cve.cvss >= 6.0:
            return True

    # 3. CVSS vector analysis: network-accessible + high impact
    if cve.cvss_vector and cve.cvss is not None and cve.cvss >= 7.0:
        vec = cve.cvss_vector.upper()
        # Network accessible, no user interaction, high confidentiality or integrity impact
        if "AV:N" in vec and "UI:N" in vec and ("C:H" in vec or "I:H" in vec):
            return True

    # 4. Description keyword matching
    if cve.description:
        desc_lower = cve.description.lower()
        for keyword in _PENTESTER_KEYWORDS:
            if keyword in desc_lower:
                return True

    # 5. Safety net: CVSS >= 9.0 is always interesting
    if cve.cvss is not None and cve.cvss >= 9.0:
        return True

    return False


# --- Gold-only filter (versioned vs versionless strategy) ---

def _cvss_tokens(cve: CVEInfo) -> set[str]:
    """Split the CVSS vector string into metric tokens, upper-cased.

    Substring matching on the raw vector string is unsafe because e.g. ``UI:N``
    contains ``I:N`` — token-wise splitting keeps metric boundaries crisp.
    """
    if not cve.cvss_vector:
        return set()
    return {t.strip().upper() for t in cve.cvss_vector.split("/") if t.strip()}


def _cve_is_local_only(cve: CVEInfo) -> bool:
    """True if the CVE requires local or physical attack vector — of marginal
    value on an external/internal network pentest unless chained from another
    foothold. We drop these by default.
    """
    tokens = _cvss_tokens(cve)
    return "AV:L" in tokens or "AV:P" in tokens


def _cve_is_physical_only(cve: CVEInfo) -> bool:
    """True if the CVE requires physical access (AV:P) — out of scope on
    every network engagement that doesn't involve a hardware lab.

    Counterpart to ``_cve_is_local_only`` for the host-OS enrichment
    path: there AV:L kernel privesc IS pentester gold (post-foothold
    escalation, e.g. CVE-2009-2698 sock_sendpage on Linux 2.6.x) so
    we still need to filter AV:P without lumping AV:L into the same
    drop.
    """
    return "AV:P" in _cvss_tokens(cve)


def _cve_is_av_local(cve: CVEInfo) -> bool:
    """True if the CVE's attack vector is local (AV:L).

    Host-OS enrichment uses this to gate AV:L kernel-privesc entries
    to owned hosts only. A 500-host engagement with a mostly-Linux
    fleet otherwise ends up with every host detail panel showing
    kernel privesc CVEs the operator cannot exercise yet — Mark-as-
    Owned is the event that flips them into actionability.
    """
    return "AV:L" in _cvss_tokens(cve)


def _cve_requires_admin(cve: CVEInfo) -> bool:
    """True if the CVE requires high-privileged access (admin/root) to exploit.

    On a pentest these are post-exploitation CVEs: if we already have admin we
    have a shell and don't need the CVE; if we don't have admin the CVE can't
    help us get one. Drop as noise. Low-privilege requirements (PR:L, PR:N)
    are retained — those are legitimate entry points after password spray or
    null-session enumeration.
    """
    return "PR:H" in _cvss_tokens(cve)


def _cve_is_dos_only(cve: CVEInfo) -> bool:
    """True if the CVE only impacts availability (pure DoS) — no confidentiality
    or integrity loss. Useless for red-team gold hunting.
    """
    tokens = _cvss_tokens(cve)
    if not tokens:
        return False
    return "C:N" in tokens and "I:N" in tokens and ("A:H" in tokens or "A:L" in tokens)


def _cve_priority_key(cve: CVEInfo):
    """Sort key for pentester-useful CVE ordering.

    Priority tiers (descending — lower tuple value sorts first):
      1. CISA-KEV listed  — actively exploited in the wild
      2. has_exploit=True — public PoC / module exists
      3. By CVSS, highest first

    A CVE with a Metasploit module and CVSS 7.4 beats a theoretical
    CVSS 9.8 CVE with no PoC on every engagement that matters.
    """
    return (
        0 if cve.in_cisa_kev else 1,
        0 if cve.has_exploit else 1,
        -(cve.cvss or 0.0),
    )


def _cve_published_year(cve: CVEInfo) -> int | None:
    """Parse publication year from the ISO timestamp NVD returns."""
    if not cve.published:
        return None
    m = re.match(r"(\d{4})", cve.published)
    return int(m.group(1)) if m else None


# Versionless "assume latest" recency horizon. NVD indexes exploit-db entries
# from the early 2000s that still carry has_exploit=True but exploit Apache 1.3
# or OpenSSH 3.x — not applicable to a current install. Five years is the
# cutoff that drops that class while keeping CVEs like CVE-2017-7494 (still
# relevant on legacy Samba in enterprise environments) when they are KEV.
_VERSIONLESS_RECENCY_YEARS = 5


def _cve_is_gold(
    cve: CVEInfo,
    versionless: bool = False,
    os_cpe: bool = False,
    host_os: bool = False,
) -> bool:
    """Decide whether a CVE clears the "actionable gold" bar for a pentester.

    Single gate: a CVE must have an actionable-exploit signal. Either NVD's
    ``has_exploit`` tag (public PoC / Metasploit module) OR a CISA-KEV
    listing satisfies it — KEV means CISA observed in-the-wild exploitation,
    so it carries the same "real attack code exists" weight as a tagged
    reference. When we have a service version, ``_cve_applies_to`` upstream
    has already confirmed the CVE's version range covers it. When we do not,
    we assume the service runs the latest release — so we additionally drop
    exploits that target ancient releases only (``versionless`` path,
    recency cut).

    "Theoretical critical" CVEs (CVSS 9.x with no PoC) were the dominant
    noise pattern on real client scans: dozens of Apache/Samba CVEs
    bulk-attached to every host with no actionable follow-up. Requiring an
    exploit signal cuts that entire class.

    KEV is NOT a free pass — historically KEV got an unconditional override
    that bypassed admin-required and versionless-recency gates. That let
    KEV-flagged CVEs through with broken CPE attribution (NVD bugs like
    CVE-2022-2586 nftables tagged against kernel 2.6) or reverse-temporal
    mismatches (CVE-2021-40438 Apache 2.4 mod_proxy tagged against 2.2.8).
    KEV now goes through the same applicability filters as any has_exploit
    CVE; the override is gone.

    Order (first matching wins):
      1. Hard rejects — AV:L/AV:P and pure-DoS drop regardless of KEV.
         CVE-2023-44487 (HTTP/2 Rapid Reset) is in CISA KEV but pure DoS.
      2. Admin-required reject — PR:H CVEs are post-exploitation, not a way in.
      3. Versionless recency reject — for "assume latest" queries, drop
         exploits registered against releases too old to still be running.
         Carve-out for OS-typed CPE queries (``os_cpe=True``): the major OS
         version is encoded in the product name (``windows_7``,
         ``windows_server_2012``, …), not the version slot, so a wildcard
         version is the normal shape rather than "we don't know the
         release." EoL'd OS families retain CVE applicability indefinitely
         — applying the 5-year recency cut to them drops every Win 7 /
         2008 / XP CVE on a clearly-vulnerable legacy host.
      4. Actionable-exploit gate — has_exploit OR in_cisa_kev.
    """
    # AV:L vs AV:P split is host-OS-context aware. For service-level
    # queries the operator is enumerating external attack surface, so
    # both local and physical CVEs drop. For host-OS queries the
    # operator already knows they need a foothold (kernel privesc
    # presumes shell access); AV:L is then the canonical
    # post-foothold escalation path and must survive the gate.
    if host_os:
        if _cve_is_physical_only(cve):
            return False
    elif _cve_is_local_only(cve):
        return False
    if _cve_is_dos_only(cve):
        return False

    if _cve_requires_admin(cve):
        return False

    if versionless and not os_cpe:
        year = _cve_published_year(cve)
        if year is not None and year < datetime.now(timezone.utc).year - _VERSIONLESS_RECENCY_YEARS:
            return False

    return cve.has_exploit or cve.in_cisa_kev


# --- NVD API queries ---

def _has_specific_version(cpe23: str) -> bool:
    """Check if CPE has a specific version (not wildcard)."""
    parts = cpe23.split(":")
    # cpe:2.3:a:vendor:product:VERSION:...
    return len(parts) >= 6 and parts[5] != "*"


def _query_nvd_cpe(
    cpe23: str,
    service_version_override: str | None = None,
    host_os: bool = False,
    host_os_cpe: str | None = None,
) -> list[CVEInfo] | None:
    """Query NVD API using CPE-based virtualMatchString.

    With specific version: full search, sorted by severity (highest first).
    Without version (wildcard): recent CVEs only, sorted by date (newest first).

    Args:
        cpe23: The CPE 2.3 string to query against NVD.
        service_version_override: When the CPE carries a wildcard version
            (``*``) but the caller still knows the service version from
            another source, thread it here so the client-side CPE
            applicability validator can do proper range matching instead
            of falling back to the "must be completely unconstrained"
            rule. Used by the wildcard-retry path: a specific-version
            query (``esxi:8.0.3``) comes back empty because VMware
            registers CVEs at major.minor, so we retry with
            ``esxi:*`` — but we still want range validation to pick the
            CVEs that apply to 8.0.3, not every CVE that ever touched
            ESXi.
        host_os: True when the caller is enriching a Host node's
            ``os_cpe`` rather than a Service's ``cpe``. Threaded into
            the gold filter so AV:L kernel privesc CVEs survive — the
            host-OS pipeline exists precisely to surface them, since
            no service-level CPE exposes them.
        host_os_cpe: The hosting box's OS CPE (CPE 2.2 or 2.3 form)
            used by the strict configuration-tree evaluator. For
            service-level enrichment this is the host that runs the
            service; for host-OS enrichment it's the same CPE we're
            querying. When ``None`` the strict eval defers.

    Returns None if CPE is not recognized by NVD (404), signaling
    the caller to try keyword fallback.
    """
    _rate_limit()

    has_version = _has_specific_version(cpe23)
    encoded_cpe = urllib.request.quote(cpe23)

    # NVD API quirk: virtualMatchString combined with pubStartDate or
    # cvssV3Severity returns HTTP 404, so we cannot server-side filter by
    # recency or severity. We request the maximum page size (2000) and
    # filter/sort client-side. Without this, flagship CVEs would be squeezed
    # out for any vendor whose NVD history exceeds 100 entries.
    url = f"{NVD_API_BASE}?virtualMatchString={encoded_cpe}&resultsPerPage=2000"

    # Extract product and version from the CPE so _execute_nvd_query can
    # validate each returned CVE's CPE configuration actually applies. For
    # wildcard CPE queries this is what drops CVEs pinned to ancient
    # versions (NVD otherwise happily returns them). The product is passed
    # as ``version_applies_product`` rather than ``product_hint`` because
    # NVD already constrained the product server-side via virtualMatchString
    # — we only need the client-side version-range cross-check.
    parts = cpe23.split(":")
    cpe_product = parts[4] if len(parts) > 4 else None
    cpe_version = parts[5] if len(parts) > 5 else None
    applies_product = cpe_product.replace("_", " ") if cpe_product else None
    if cpe_version and cpe_version not in ("*", "-"):
        version_hint = cpe_version
    else:
        # CPE version is wildcard — caller may still know the service
        # version (wildcard-retry path). Use it so we keep range/major-minor
        # matching instead of dropping to the "unconstrained only" rule.
        extracted = _extract_version(service_version_override) if service_version_override else "*"
        version_hint = extracted if extracted and extracted != "*" else None

    # ``parts[2]`` is the CPE 2.3 part-type slot (``a`` / ``o`` / ``h``).
    # ``o`` flips two downstream behaviours: the strict-applicability
    # filter inside ``_execute_nvd_query`` skips its version-slot check
    # (NVD's OS records use the ``-`` NA marker with the SP and edition
    # in update/edition slots, which the application rule wrongly treats
    # as constrained), and the versionless recency cut in
    # ``_cve_is_gold`` is suppressed (legacy OS families retain CVE
    # applicability indefinitely).
    is_os_cpe = len(parts) > 2 and parts[2] == "o"

    # For host-OS queries the queried CPE IS the host's OS — use it as
    # platform context too. For service queries the caller threads the
    # host's os_cpe in via ``host_os_cpe``.
    effective_platform = host_os_cpe or (cpe23 if is_os_cpe else None)

    cves = _execute_nvd_query(
        url, f"CPE:{cpe23}",
        version_hint=version_hint,
        version_applies_product=applies_product,
        os_cpe=is_os_cpe,
        host_os_cpe=effective_platform,
    )

    # None = 404 (CPE not in NVD) — signal caller to try keyword fallback
    if cves is None:
        return None

    # Mark each CVE with whether the query had a pinned version anchor.
    # ``has_version`` is True when the CPE itself carries a non-wildcard
    # version; even when it's False, a ``service_version_override`` from
    # the wildcard-retry path can supply a known version. Downstream
    # ``_upsert_vulnerability`` stores the inverse on the HAS_VULN edge
    # as ``r.version_unconfirmed`` so per-edge reporting tells the truth
    # for sub-product matches even when the service has no primary
    # version (compound banners on Apache+mod_ssl, etc.).
    version_pinned = has_version or bool(version_hint)
    for cve in cves:
        cve.matched_version_pinned = version_pinned

    # Coarse pentester filter first (CWE + pattern), then the gold filter
    # requires an actionable public exploit (KEV overrides). Hard rejects
    # (local/DoS/admin-required) apply in both paths; the versionless path
    # also cuts CVEs published too long ago to plausibly affect "latest"
    # — except when the CPE is OS-typed, where ``is_os_cpe`` (already
    # computed above) suppresses the recency cut so EoL'd OS families
    # retain CVE applicability indefinitely.
    cves = [c for c in cves if _is_pentester_relevant(c)]
    cves = [c for c in cves if _cve_is_gold(
        c, versionless=not has_version, os_cpe=is_os_cpe, host_os=host_os,
    )]

    # Pentester-priority sort: CISA KEV (active in-the-wild exploitation)
    # first, then CVEs with a public exploit, then CVSS descending within
    # each tier. A low-CVSS CVE with a Metasploit module is more useful
    # than a high-CVSS theoretical one.
    cves.sort(key=_cve_priority_key)
    # Result cap. The host-OS pass needs a larger window than service-level
    # queries: the kernel CPE universe is thousands of CVEs deep and the
    # priority-sorted band of CVSS 7-8 LPE bugs (the actionable post-foothold
    # privesc tier) starts around position 20 on legacy kernels like Linux
    # 2.6. Without a wider cap, sister LPE CVEs at the same CVSS tier (e.g.
    # CVE-2009-2692 sock_sendpage at position 21 next to CVE-2009-2698
    # udp_sendmsg at 22) get split by the cap and only one of the pair
    # surfaces. 200 keeps the full actionable band on every Linux host-OS
    # query while still bounding the per-host attachment. Service-level
    # queries keep the historical 20/50 caps -- their universe is much
    # smaller and the same band-splitting risk doesn't apply.
    if host_os:
        return cves[:200]
    return cves[:20 if has_version else 50]


def _query_nvd_keyword(
    product: str, version: str, host_os_cpe: str | None = None,
) -> list[CVEInfo]:
    """Query NVD API using keywordSearch (fallback, less precise).

    Validates results against CVE's CPE configurations to ensure the CVE
    actually affects the target product, not just mentions it.

    NVD quirk: keywordSearch combined with pubStartDate returns HTTP 404,
    so date-restriction is not available server-side. With a versionless
    query we drop ``keywordExactMatch`` to allow vendor-only searches (e.g.
    "Veeam Backup" finding CVEs assigned to full "Veeam Backup & Replication"
    products); the pentester CWE filter + severity sort compensates.

    ``host_os_cpe`` flows into the strict configuration-tree evaluator so
    keyword-search results also benefit from AND-config / platform-context
    rejection.
    """
    _rate_limit()

    versionless = not version or version == "*"
    keyword = product.strip() if versionless else f"{product} {version}".strip()
    encoded = urllib.request.quote(keyword)
    url = f"{NVD_API_BASE}?keywordSearch={encoded}&resultsPerPage=50"
    if not versionless:
        url += "&keywordExactMatch"

    cves = _execute_nvd_query(
        url, f"keyword:{keyword}",
        product_hint=product,
        version_hint=version if not versionless else None,
        host_os_cpe=host_os_cpe,
    ) or []

    # Same two-stage filter as the CPE path — coarse CWE+pattern relevance,
    # then the strict actionable-exploit gate with KEV soft override. The
    # versionless flag tracks whether we had a real version to anchor the
    # CVE against, same semantics as the CPE path.
    cves = [c for c in cves if _is_pentester_relevant(c)]
    cves = [c for c in cves if _cve_is_gold(c, versionless=versionless)]

    # Same pentester-priority sort as the CPE path.
    cves.sort(key=_cve_priority_key)

    return cves[:20 if versionless else 10]


def _execute_nvd_query(
    url: str,
    context: str,
    product_hint: str | None = None,
    version_hint: str | None = None,
    version_applies_product: str | None = None,
    os_cpe: bool = False,
    host_os_cpe: str | None = None,
    _retries: int = 0,
) -> list[CVEInfo] | None:
    """Execute NVD API request and parse results.

    Args:
        url: NVD API URL to query.
        context: Human-readable context for logging.
        product_hint: If set, validate each CVE's CPE configurations
            actually reference this product via substring match (used by
            the keyword-search fallback, where NVD itself does not
            constrain the product).
        version_hint: If set, cross-check the CVE's CPE configuration
            against this version so CVEs pinned to unrelated versions
            (e.g. CVE-2004-0492 tagged at ``apache:http_server:1.3.31``)
            are not attached to modern installs. Critical for wildcard
            CPE queries where NVD does not filter version server-side.
        version_applies_product: Product name to drive the version
            applicability filter independently of ``product_hint``. The
            CPE-query path sets this without the substring filter because
            NVD already constrained product server-side — we only need
            to validate the version range.
        host_os_cpe: Host's OS CPE (CPE 2.2 or 2.3 form) used by the
            strict configuration-tree evaluator to reject CVEs whose
            NVD AND-configs require a platform context our host doesn't
            satisfy (e.g. mod_isapi requires Microsoft Windows; a
            general-purpose Linux box can never match). When ``None``
            the strict eval defers — it never over-filters on missing
            context.
        _retries: Internal retry counter (max 2 retries on 403).

    Returns:
        List of CVEInfo, or None if CPE not found (404) — signals
        the caller to try keyword fallback.
    """
    headers = {"User-Agent": "Cauldron/0.1.0"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    req = urllib.request.Request(url, headers=headers)

    try:
        resp = urllib.request.urlopen(req, timeout=_NVD_REQUEST_TIMEOUT)
        # Chunked read tolerates connections the server closes early —
        # NVD's response for ``cpe:2.3:o:linux:linux_kernel:*`` runs
        # ~19 MB and the default ``resp.read()`` regularly hits
        # ``http.client.IncompleteRead`` on home connections. Reading
        # incrementally surfaces the same exception (caught below) but
        # at least we already have the partial bytes if a future fix
        # wants to salvage them.
        body = bytearray()
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            body.extend(chunk)
        data = json.loads(bytes(body))
    except http.client.IncompleteRead as e:
        # NVD truncated the response mid-stream (most common on the
        # multi-megabyte responses ``cpe:/o:linux:linux_kernel:*``
        # produces). Treat as transient so the caller skips the cache —
        # poisoning the 7-day cache with a partial answer would
        # silently hide thousands of kernel privesc CVEs from every
        # subsequent boil. Retry budget mirrors the network-error path.
        if _retries < _NVD_RETRY_BUDGET:
            backoff = 5 * (2 ** _retries)
            logger.warning(
                "NVD IncompleteRead for %s (%d bytes received). Retry %d/%d, waiting %ds...",
                context, len(e.partial), _retries + 1, _NVD_RETRY_BUDGET, backoff,
            )
            time.sleep(backoff)
            return _execute_nvd_query(
                url, context, product_hint, version_hint, version_applies_product,
                os_cpe, host_os_cpe, _retries + 1,
            )
        logger.error(
            "NVD IncompleteRead for %s after %d retries (%d bytes) — not cacheable",
            context, _NVD_RETRY_BUDGET, len(e.partial),
        )
        raise NvdTransientError(
            f"NVD truncated response for {context} ({len(e.partial)} bytes)"
        ) from e
    except urllib.error.HTTPError as e:
        # 403 = rate limit, 503 = service unavailable — both retryable
        if e.code in (403, 429, 500, 502, 503, 504) and _retries < _NVD_RETRY_BUDGET:
            backoff = 15 * (2 ** _retries)  # 15s, 30s, 60s, 120s, 240s, 480s
            logger.warning(
                "NVD API error %d for %s. Retry %d/%d, waiting %ds...",
                e.code, context, _retries + 1, _NVD_RETRY_BUDGET, backoff,
            )
            time.sleep(backoff)
            return _execute_nvd_query(
                url, context, product_hint, version_hint, version_applies_product,
                os_cpe, host_os_cpe, _retries + 1,
            )
        if e.code == 404:
            logger.info("NVD CPE not found (404) for %s — will try keyword fallback", context)
            return None
        # Non-404 HTTP error after retries (or a 4xx we do not retry). Raise
        # so the caller skips caching — a 401 / 400 / 5xx-after-retries is
        # not an authoritative "zero CVEs" answer and must not poison the
        # 7-day cache with a false negative.
        logger.error("NVD API error %d for %s — not cacheable", e.code, context)
        raise NvdTransientError(f"HTTP {e.code} from NVD for {context}") from e
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        # Transient network error — retry with exponential backoff
        if _retries < _NVD_RETRY_BUDGET:
            backoff = 5 * (2 ** _retries)  # 5s, 10s, 20s, 40s, 80s, 160s
            logger.warning(
                "NVD API request failed for %s: %s. Retry %d/%d, waiting %ds...",
                context, e, _retries + 1, _NVD_RETRY_BUDGET, backoff,
            )
            time.sleep(backoff)
            return _execute_nvd_query(
                url, context, product_hint, version_hint, version_applies_product,
                os_cpe, host_os_cpe, _retries + 1,
            )
        logger.error("NVD API request failed for %s after %d retries: %s", context, _NVD_RETRY_BUDGET, e)
        raise NvdTransientError(f"NVD unreachable for {context}: {e}") from e

    # Normalize product hint for matching
    product_lower = product_hint.lower().strip() if product_hint else None
    applies_product = (
        version_applies_product.lower().strip() if version_applies_product else product_lower
    )

    cves = []
    for vuln_item in data.get("vulnerabilities", []):
        cve_data = vuln_item.get("cve", {})

        # Filter rejected/disputed CVEs
        status = cve_data.get("vulnStatus", "")
        if status in ("Rejected", "Disputed"):
            continue

        # Validate product match for keyword searches (eliminate false positives)
        if product_lower and not _cve_matches_product(cve_data, product_lower):
            continue

        # Validate that the CVE's CPE config is actually applicable to our
        # service version. Without this check, NVD's wildcard virtualMatchString
        # happily returns CVEs pinned to ancient versions (e.g. CVE-1999-0067
        # tagged at apache:http_server:1.0.3 attaching to modern Apache 2.4).
        if applies_product and not _cve_applies_to(
            cve_data, applies_product, version_hint, os_cpe=os_cpe,
        ):
            continue

        # Strict configuration-tree evaluation. ``_cve_applies_to`` checked
        # that the version-range alone fits; this layer verifies the full
        # AND/OR/negate/vulnerable-flag structure of NVD's configurations.
        # Catches CVEs whose AND-configs require a platform/hardware context
        # that our host can never satisfy (mod_isapi requiring Windows; an
        # OpenSSH bug gated by SonicWall/NetApp appliance). Defers when
        # host_os_cpe is unknown — never over-filters on missing context.
        if applies_product and not _cve_configurations_match(
            cve_data, applies_product, version_hint, host_os_cpe,
        ):
            continue

        cve = _parse_cve(cve_data)
        if cve:
            cves.append(cve)

    return cves


def _cpe_matches_product(criteria: str, product_lower: str) -> bool:
    """Check whether a CPE criteria string references the target product."""
    c = criteria.lower()
    if product_lower in c:
        return True
    normalized = product_lower.replace(" ", "_").replace("-", "_")
    return normalized in c


def _iter_matching_cpe_entries(cve_data: dict, product_lower: str):
    """Yield cpeMatch dicts from the CVE that reference our target product."""
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if _cpe_matches_product(criteria, product_lower):
                    yield match


# ---------------------------------------------------------------------------
# Strict NVD configuration-tree evaluation
# ---------------------------------------------------------------------------
#
# ``_cve_applies_to`` (above) handles the common case: does our service version
# fall in the cpeMatch range for our product? But NVD encodes a richer truth
# in ``configurations[]``: AND/OR operators, ``vulnerable: true|false`` per
# match, ``negate`` on nodes. The flat per-product version-range check
# silently drops every constraint that involves the *running environment*
# rather than just the product version.
#
# Concrete miss: CVE-2010-0425 (mod_isapi) ships an AND-config that says
# "vulnerable Apache 2.0.37..2.0.64 AND running on Microsoft Windows". A
# Linux Apache 2.0.52 install hits the first node (version in range) and
# Cauldron stops there — but the AND requires the Windows node too, which
# never matches Linux. The CVE is mathematically inapplicable and we used
# to attach it anyway.
#
# The helpers below evaluate the configuration tree strictly. They are an
# ADDITIVE filter on top of ``_cve_applies_to``: a CVE that already passed
# the version-range gate must also satisfy at least one top-level config
# under proper AND/OR/negate semantics. When the platform context is
# unknown (no os_cpe on the host), the check defers — we cannot prove
# rejection, so we keep the finding for the existing filters to handle.


def _cpe_parts(cpe: str) -> tuple[str, str, str, str, str, str] | None:
    """Split a CPE 2.3 criteria string into ``(part, vendor, product, version,
    update, target_sw)``. Returns ``None`` on malformed input."""
    parts = cpe.lower().split(":")
    if len(parts) < 11:
        return None
    return (parts[2], parts[3], parts[4], parts[5], parts[6], parts[10])


def _running_os_matches_cpe(criteria: str, our_os_cpe: str | None) -> bool:
    """True if our scanned host's OS (``our_os_cpe``) plausibly satisfies the
    given CPE criteria string. Used to evaluate AND-config *context* nodes
    that constrain "running on platform X".

    Conservative defaults — we only reject when the platform mismatch is
    unambiguous; ambiguous cases (unknown host OS, application-level
    contexts we can't verify) defer to ``True``:

    - ``part='o'`` (OS context): matches when the criteria's vendor and
      product appear in our os_cpe. ``cpe:/o:microsoft:windows:-`` is rejected
      by a Linux host because neither "microsoft" nor "windows" appear in
      ``cpe:/o:linux:linux_kernel:2.6``.
    - ``part='h'`` (hardware context): only matches when our os_cpe (rare)
      explicitly references the same vendor/product. A Linux host running on
      generic x86 never matches a SonicWall / NetApp / Fujitsu hardware
      criteria — this is where AND-configs for vendor-specific appliances
      cleanly drop on a general-purpose box.
    - ``part='a'`` (application context, e.g. "vulnerable when used with
      Apache"): defers to ``True``. The scan may have the app installed
      under a different banner; rejecting on app-context would generate
      false negatives we can't recover from.
    - Unknown ``part`` / malformed CPE: defers to ``True``.
    """
    cpe_parts = _cpe_parts(criteria)
    if cpe_parts is None:
        return True
    part, vendor, product, _ver, _update, _target_sw = cpe_parts

    if part == "a":
        # Application-context constraints (e.g. "vulnerable when used with
        # OpenSSL") need install-level knowledge we don't have at NVD-query
        # time. Defer to the version-range filter and AI Phase 3.
        return True

    if our_os_cpe is None:
        # No host OS context — can't prove a mismatch, must defer.
        return True

    our = our_os_cpe.lower()

    if part == "o":
        # OS context: the criteria's vendor and product must appear in our
        # os_cpe. ``cpe:/o:linux:linux_kernel`` is matched by a context CPE
        # like ``cpe:2.3:o:linux:linux_kernel:*`` but not by
        # ``cpe:2.3:o:microsoft:windows:-``.
        return vendor in our and product in our

    if part == "h":
        # Hardware context (router / appliance / NAS): only matches when
        # the same hardware vendor+product appears in our os_cpe. General-
        # purpose Linux/Windows hosts never carry that info, so AND-configs
        # gated by ``h:netapp:cn1610`` etc. fail cleanly.
        return vendor in our and product in our

    return True


def _evaluate_config_node(
    node: dict,
    product_lower: str | None,
    version: str | None,
    our_os_cpe: str | None,
) -> bool:
    """Evaluate a single configuration node against our scan context.

    A node is a list of ``cpeMatch`` entries joined by OR (one-of). The
    ``negate`` flag inverts the result.

    Each cpeMatch entry is one of two kinds:

    - ``vulnerable: true`` — describes the vulnerable software. Matches
      when criteria.product equals our product and our version falls in
      the entry's range (or matches the entry's pinned version).
    - ``vulnerable: false`` — describes the running environment context.
      Matches when our host's OS plausibly satisfies the criteria
      (``_running_os_matches_cpe``).

    We default to a permissive match (return True) when the scan context
    is incomplete — strict eval is meant to *reject*, never to over-filter
    a finding the cheaper checks already kept.
    """
    for match in node.get("cpeMatch", []):
        criteria = match.get("criteria", "")
        is_vuln_entry = match.get("vulnerable", True)

        if is_vuln_entry:
            if product_lower and _cpe_matches_product(criteria, product_lower):
                if version:
                    if _cpe_entry_version_in_range(match, version):
                        return not node.get("negate", False)
                else:
                    if not _cpe_entry_has_version_constraint(match):
                        return not node.get("negate", False)
            # Vuln entry that doesn't match our product — keep scanning the
            # other entries in this node.
            continue

        # Context (vulnerable=false) entry — match against host OS.
        if _running_os_matches_cpe(criteria, our_os_cpe):
            return not node.get("negate", False)

    return node.get("negate", False)


def _evaluate_top_config(
    config: dict,
    product_lower: str | None,
    version: str | None,
    our_os_cpe: str | None,
) -> bool:
    """Evaluate one top-level configuration entry.

    Nodes are combined according to the config's ``operator`` field
    (``AND`` or ``OR``, defaulting to ``OR``).
    """
    nodes = config.get("nodes", [])
    if not nodes:
        return True  # malformed config — defer
    op = config.get("operator", "OR")
    if op == "AND":
        return all(
            _evaluate_config_node(n, product_lower, version, our_os_cpe)
            for n in nodes
        )
    return any(
        _evaluate_config_node(n, product_lower, version, our_os_cpe)
        for n in nodes
    )


def _normalize_os_family(os_cpe: str | None) -> str:
    """Collapse an os_cpe (CPE 2.2 or 2.3 form) into a coarse family token.

    The strict configuration-tree evaluator only needs the OS family to
    answer "could this platform-context node match?"; AND-config nodes
    distinguish Linux vs Windows vs hardware-vendor, never major-minor
    kernel version. Folding "Linux 2.6" / "Linux 5.10" / "Ubuntu 22" all
    to ``'linux'`` keeps the CVE cache from fragmenting per-kernel-version
    while still letting us reject Windows-only AND-configs on Linux hosts.

    Returns ``'unknown'`` when the CPE doesn't carry enough info — the
    strict eval defers in that case.
    """
    if not os_cpe:
        return "unknown"
    c = os_cpe.lower()
    if "linux" in c or "fedora" in c or "debian" in c or "ubuntu" in c or "redhat" in c or "rhel" in c or "centos" in c:
        return "linux"
    if "windows" in c or "microsoft" in c:
        return "windows"
    if "macos" in c or "mac_os" in c or "darwin" in c or "apple" in c:
        return "macos"
    if "bsd" in c:
        return "bsd"
    if "solaris" in c or "sunos" in c:
        return "solaris"
    return "unknown"


def _cve_configurations_match(
    cve_data: dict,
    product_lower: str | None,
    version: str | None,
    our_os_cpe: str | None,
) -> bool:
    """Strict mathematical applicability check against NVD's configuration tree.

    Returns False ONLY when every top-level configuration unambiguously
    fails to match our scan context — that proves the CVE cannot apply.
    Returns True when at least one configuration matches OR when ambiguity
    prevents proof of rejection (no configurations on the CVE, unknown
    host platform, application-context constraints we can't verify, etc.).

    The top level of ``configurations[]`` is OR — a CVE applies if ANY
    top-level config matches. Per-config AND/OR is handled by
    ``_evaluate_top_config``.

    This is layered on top of ``_cve_applies_to``: cheap version-range
    filtering catches most noise, then strict eval rejects the residue of
    CVEs whose AND-configs require a platform / hardware context we don't
    satisfy (Apache mod_isapi requiring Windows, OpenSSH CVE gated by a
    specific NetApp appliance, etc.).
    """
    configs = cve_data.get("configurations", [])
    if not configs:
        return True  # description-based match owns this case
    return any(
        _evaluate_top_config(cfg, product_lower, version, our_os_cpe)
        for cfg in configs
    )


def _cpe_entry_has_version_constraint(match: dict) -> bool:
    """True if a cpeMatch entry pins versions in any way we cannot verify
    against an unknown service version.

    Covers:
    - Explicit bounded ranges (versionStart/End*).
    - Specific version baked into the criteria (``...:1.0.3:...``).
    - NA marker ``-`` in the CPE version field. Per CPE 2.3 spec ``-``
      means "not applicable" — NVD often uses it for broken entries that
      predate version ranges (e.g. CVE-1999-1237 tagged at
      ``apache:http_server:-``). Treat as constrained: we cannot confirm
      the CVE applies to a modern install.

    Returns False only for truly unconstrained ``*`` entries without range.
    """
    if any(match.get(k) for k in (
        "versionStartIncluding", "versionStartExcluding",
        "versionEndIncluding", "versionEndExcluding",
    )):
        return True
    criteria = match.get("criteria", "")
    parts = criteria.split(":")
    if len(parts) < 6:
        return False
    cpe_ver = parts[5]
    return cpe_ver != "*"


def _cpe_entry_version_in_range(match: dict, version_str: str) -> bool:
    """Check if the provided service version falls in the cpeMatch's range
    (or equals the pinned specific version at major.minor level).

    Returns True when the version is applicable OR when the entry has no
    version constraint at all. Returns False when the entry pins versions
    and our version is outside the applicable range.
    """
    try:
        from packaging.version import InvalidVersion, Version
    except ImportError:  # packaging is a transitive dep; defensive
        return True

    try:
        ours = Version(_extract_version(version_str))
    except InvalidVersion:
        return True  # unparseable — don't over-filter

    def _v(raw: str | None) -> "Version | None":
        if not raw:
            return None
        try:
            return Version(raw)
        except InvalidVersion:
            return None

    start_inc = _v(match.get("versionStartIncluding"))
    start_exc = _v(match.get("versionStartExcluding"))
    end_inc = _v(match.get("versionEndIncluding"))
    end_exc = _v(match.get("versionEndExcluding"))

    if start_inc or start_exc or end_inc or end_exc:
        if start_inc and ours < start_inc:
            return False
        if start_exc and ours <= start_exc:
            return False
        if end_inc and ours > end_inc:
            return False
        if end_exc and ours >= end_exc:
            return False
        return True

    # No explicit range — check the version field embedded in the CPE string.
    parts = match.get("criteria", "").split(":")
    if len(parts) < 6:
        return True
    cpe_ver_raw = parts[5]
    if cpe_ver_raw == "*":
        return True  # wildcard CPE: unconstrained, applies to any version
    if cpe_ver_raw in ("-", ""):
        return False  # NA marker — NVD says "version not applicable"; cannot confirm
    pinned = _v(cpe_ver_raw)
    if not pinned:
        return True
    # Pinned to a specific version — require our major.minor to match so a
    # 1999 CVE tagged at ``1.0.3`` never attaches to a modern 2.4 deploy.
    return ours.major == pinned.major and ours.minor == pinned.minor


def _cve_applies_to(
    cve_data: dict,
    product_lower: str,
    version: str | None,
    os_cpe: bool = False,
) -> bool:
    """Validate that a CVE's CPE configuration actually covers our service.

    The NVD ``virtualMatchString`` endpoint is generous: it returns every CVE
    whose CPE configuration mentions the vendor:product, regardless of the
    version pinned in that configuration. When our service is versionless
    (the caller queried with a wildcard) NVD cannot filter for us, so we
    would otherwise pick up ancient CVEs pinned to versions from decades ago
    (CVE-1999-0067 tagged at ``apache:http_server:1.0.3`` on modern Apache).

    Logic:
    - No cpeMatch entries for this product → fall back to loose check.
    - OS-typed CPE in versionless mode → keep on product match. See ``os_cpe``.
    - Versionless application service → require at least one unconstrained
      CPE entry for this product. Any CPE pinned to a specific version or
      bounded range drops the CVE because we cannot confirm applicability.
    - Versioned service → require at least one CPE entry whose range (or
      pinned specific version at major.minor) covers the service version.

    Args:
        os_cpe: True when the upstream query was against an OS-typed CPE
            (``cpe:2.3:o:microsoft:windows_7:*:…``). NVD's older OS CVE
            records (most of the 2017-and-earlier Windows backlog,
            including CVE-2017-0144 EternalBlue) use the ``-`` "NA"
            marker in the version slot with the SP/edition encoded in
            the ``update`` and ``edition`` slots — e.g.
            ``cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:x64:*``. The
            generic application-CPE rule treats ``-`` as constrained and
            drops these, taking MS17-010 and most of the Win 7 / 2008 /
            XP backlog with it. For OS-typed queries the product name
            itself carries the OS identity and the version slot's value
            (``-``, ``*``, build number, …) isn't a meaningful
            applicability filter — skip the version check entirely and
            rely on the product-name match from ``_iter_matching_cpe_entries``.
    """
    configurations = cve_data.get("configurations", [])
    if not configurations:
        return True  # keep; description-based match handled by _cve_matches_product

    matches = list(_iter_matching_cpe_entries(cve_data, product_lower))
    if not matches:
        return True  # different product entry; not our business to drop

    versionless = not version or _extract_version(version) == "*"
    if versionless:
        if os_cpe:
            # See ``os_cpe`` arg docstring — product match is the whole
            # applicability check for OS CPEs.
            return True
        # Without a service version we cannot prove a range-bound CVE
        # applies. The old rule kept CVEs whose CPE config had ANY
        # range (versionStart/End*), assuming "range = legitimate
        # modern-vendor CVE." But this lets modern Samba CVEs (range
        # 3.5.0-4.6.4) land on a versionless Samba service that could
        # equally be Samba 2.2.x running on Kioptrix — and the
        # operator can't tell the false positives from the real
        # findings without manually cross-referencing every CPE
        # config.
        #
        # New rule: keep only when at least one CPE entry is truly
        # unconstrained (version=``*`` with no range markers).
        # Unconstrained = "this CVE affects every version of the
        # product" — that claim holds regardless of which version
        # is actually running. Range-bound CVEs (we don't know if
        # our version is in or out of the range) get dropped here.
        #
        # FN recovery path: the operator re-scans with
        # ``--script smb-version,smb-os-discovery`` (or similar) to
        # upgrade the service to versioned, then re-enriches.
        # Versioned services skip this branch entirely and use the
        # range-comparison logic below.
        return any(not _cpe_entry_has_version_constraint(m) for m in matches)

    # Versioned: require the service version to fall inside at least one
    # entry's range (or to match a pinned version at major.minor).
    return any(_cpe_entry_version_in_range(m, version) for m in matches)


def _cve_matches_product(cve_data: dict, product_lower: str) -> bool:
    """Check if a CVE actually affects the given product.

    Validates against the CVE's CPE configurations (affected products list).
    If the CVE has no CPE configurations, falls back to description check.
    """
    configurations = cve_data.get("configurations", [])

    if not configurations:
        # No CPE data — fall back to description check
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                if product_lower in desc.get("value", "").lower():
                    return True
        return False

    # Check if any CPE match node references our product
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "").lower()
                # CPE format: cpe:2.3:a:vendor:product:version:...
                # Check if product name appears in the CPE string
                if product_lower in criteria:
                    return True
                # Also check with underscores/hyphens normalized
                normalized = product_lower.replace(" ", "_").replace("-", "_")
                if normalized in criteria:
                    return True

    return False


# Attack-surface classification used to live here as ~200 lines of
# regex/keyword/CWE maps that pre-computed which L7 protocol a CVE
# attacked, fed AI triage as a [SURFACE_MISMATCH] flag, and was rendered
# as a UI badge. After the metadata-only pivot, the classifier became a
# redundant pre-filter — AI already sees the CVE description and the
# service name and can derive the same conclusion. The full host service
# list is now passed to the triage prompt, giving AI better context than
# any structural shortcut (e.g. recognising that a CrushFTP SFTP host
# without an exposed WebInterface has no path for an HTTP-only CVE).
# All classifier code, the ``v.attack_surfaces`` field, and the
# migration sweep have been removed.


def _parse_cve(cve_data: dict) -> CVEInfo | None:
    """Parse a single CVE entry from NVD API response."""
    cve_id = cve_data.get("id")
    if not cve_id:
        return None

    # Description (English)
    description = ""
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    # CVSS score — prefer the newest methodology NVD exposes. Since late
    # 2023 NVD has been tagging new CVEs with v4.0 (``cvssMetricV40``);
    # without it in the chain post-2024 CVEs came back as cvss=None and
    # the UI showed "N/A" on fresh findings. v40/v31/v30 all share the
    # same inner shape (cvssData.{baseScore, vectorString, baseSeverity}),
    # so the same branch handles all three. v2's severity field sits at
    # the entry level, not inside cvssData — that asymmetry is NVD's,
    # not ours, and stays in its own branch below.
    cvss = None
    cvss_vector = None
    severity = None
    metrics = cve_data.get("metrics", {})

    for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        if metric_key in metrics and metrics[metric_key]:
            cvss_data = metrics[metric_key][0].get("cvssData", {})
            cvss = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            severity = cvss_data.get("baseSeverity")
            break

    if cvss is None and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
        cvss = cvss_data.get("baseScore")
        cvss_vector = cvss_data.get("vectorString")
        severity = metrics["cvssMetricV2"][0].get("baseSeverity")

    # Check for known exploits in references.
    #
    # Primary signal: NVD's own "Exploit" tag on a reference. Coverage is
    # uneven for pre-2010 CVEs (NVD's tagging system was retrofitted), so
    # we also recognize a few path-scoped URL patterns that are nearly
    # always PoC hosts -- enough to catch famous old-system vulns (Slapper,
    # Samba trans2open) that NVD never backfilled with an Exploit tag.
    #
    # Path-scoped, not domain-scoped: rapid7.com is mostly marketing, but
    # /db/modules/exploit/ is the Metasploit-module catalog. Same for
    # packetstormsecurity.com -- the front page is news, but /files/ is
    # the upload archive where actual PoCs live.
    has_exploit = False
    exploit_url = None
    for ref in cve_data.get("references", []):
        tags = ref.get("tags", [])
        if "Exploit" in tags:
            has_exploit = True
            exploit_url = ref.get("url")
            break
        ref_url = ref.get("url", "")
        ref_url_l = ref_url.lower()
        if (
            "exploit-db.com" in ref_url_l
            or ("github.com" in ref_url_l and "exploit" in ref_url_l)
            or "packetstormsecurity.com/files/" in ref_url_l
            or ("rapid7.com" in ref_url_l and "/db/modules/exploit/" in ref_url_l)
        ):
            has_exploit = True
            exploit_url = ref_url
            break

    # Cross-reference ExploitDB + Metasploit. NVD's ``Exploit``-tagged
    # reference signal is incomplete on classic CVEs — the analyst
    # process tagging is patchy for the 2002-2012 era, where Metasploit
    # modules and exploit-db entries pre-date the NVD-side tagging
    # discipline. CVE-2007-2447 (Samba usermap RCE) is the canary: every
    # searchsploit hit on ``samba 3.0.20`` returns a Metasploit-included
    # exploit, yet NVD tags zero of its references ``Exploit`` — so the
    # block above leaves ``has_exploit=False`` and the gold filter
    # silently drops the finding. ``EXPLOIT_INDEX`` consults the
    # authoritative ExploitDB CSV + Metasploit modules JSON (both
    # disk-cached, weekly refresh) to fill that gap.
    #
    # Augmentation contract — never demote:
    #   - NVD True → stays True; the index can add more sources but
    #     can't flip ``has_exploit`` to False.
    #   - NVD False → becomes True iff the index has at least one
    #     reference for this CVE id. The gold filter is unchanged;
    #     only its ``has_exploit`` input becomes more accurate.
    #   - The index lookup is a pure dict read (zero network calls per
    #     CVE) — the ``boil --nvd`` orchestrator refreshes the index
    #     once per pass via ``EXPLOIT_INDEX.refresh()`` before the
    #     enrichment loop begins.
    sources: set[str] = set()
    if has_exploit:
        sources.add("nvd")
    try:
        from cauldron.exploits.exploit_index import EXPLOIT_INDEX
        index_refs = EXPLOIT_INDEX.references(cve_id)
    except Exception:  # noqa: BLE001 — index is augmentation-only; never fatal
        index_refs = []
    if index_refs:
        for r in index_refs:
            sources.add(r.source)
        if not has_exploit:
            has_exploit = True
            # First index ref's URL becomes the surfaced exploit_url so
            # the UI can deep-link to e.g. https://www.exploit-db.com/exploits/16320
            # even when NVD itself didn't carry an Exploit-tagged ref.
            exploit_url = index_refs[0].url

    # Stable joined order: ``nvd`` first, then ``exploitdb``, then ``metasploit``.
    # Single source of truth for downstream filtering / display.
    exploit_sources = "+".join(s for s in ("nvd", "exploitdb", "metasploit") if s in sources)

    # Extract CWE IDs
    cwe_ids: list[str] = []
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            cwe_val = desc.get("value", "")
            if cwe_val.startswith("CWE-"):
                cwe_ids.append(cwe_val)

    # Publication date
    published = cve_data.get("published")

    # CISA Known Exploited Vulnerabilities — NVD exposes cisaExploitAdd when
    # the CVE is in the federal catalog of actively-exploited vulnerabilities.
    # This is a much stronger signal than has_exploit (PoC existence) because
    # it means confirmed in-the-wild exploitation by ransomware groups / APTs.
    cisa_kev_added = cve_data.get("cisaExploitAdd")
    in_cisa_kev = bool(cisa_kev_added)

    return CVEInfo(
        cve_id=cve_id,
        cvss=cvss,
        cvss_vector=cvss_vector,
        severity=severity,
        description=_truncate_at_word(description, 1000),
        has_exploit=has_exploit,
        exploit_url=exploit_url,
        exploit_sources=exploit_sources,
        cwe_ids=cwe_ids,
        published=published,
        in_cisa_kev=in_cisa_kev,
        cisa_kev_added=cisa_kev_added,
    )


def _truncate_at_word(text: str, max_chars: int) -> str:
    """Cut a long string near max_chars, on a whitespace boundary, with an ellipsis.

    NVD descriptions used to be hard-sliced at 500 characters via ``[:500]``,
    which routinely cut mid-word ("the specific data depends on many factors
    incl") -- ugly in the markdown report and made the description harder
    to read at the breakpoint. This helper:

      - Returns the text unchanged if it's already within budget.
      - Otherwise rewinds to the previous whitespace and appends ``…``.
      - Falls back to a hard slice when no whitespace exists in the
        budget window (defensive — keeps the function total).
    """
    if not text or len(text) <= max_chars:
        return text or ""
    cut = text[:max_chars]
    last_space = cut.rfind(" ")
    if last_space > max_chars * 0.5:  # keep at least half the budget
        cut = cut[:last_space]
    return cut.rstrip(" .,;:") + "…"


# --- Public API ---

def enrich_service(
    product: str,
    version: str,
    cache: CVECache | None = None,
    cpe_list: list[str] | None = None,
    extra_info: str | None = None,
    script_outputs: list[str] | None = None,
    host_os_cpe: str | None = None,
) -> EnrichmentResult:
    """Find CVEs for a specific service.

    Builds the full set of CPE candidates (nmap-emitted plus sub-product
    tokens resolved via NVD's CPE Dictionary), queries NVD per candidate,
    and unions the results. Falls back to keyword search only when no
    candidate yields anything.

    Args:
        product: Software product name (e.g. "OpenSSH", "Apache httpd")
        version: Version string (e.g. "7.4", "2.4.49")
        cache: Optional CVE cache instance.
        cpe_list: CPE URIs from nmap service detection.
        extra_info: nmap's ``<service extrainfo="...">`` attribute -- often
            contains sub-product info ("(Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b")
            that doesn't reach the structured product/version fields.
        script_outputs: NSE script outputs for this service (e.g.
            http-server-header), used to extract sub-product tokens.
        host_os_cpe: Hosting box's OS CPE, threaded into the strict
            configuration-tree evaluator so service-level CVEs with
            AND-config / platform-context constraints can be rejected
            mathematically.

    Returns:
        EnrichmentResult with found CVEs.
    """
    if not product:
        return EnrichmentResult(product="", version=version or "", error="Missing product")

    if cache is None:
        cache = CVECache()

    # Build the full candidate list. Sub-product tokens (mod_ssl, OpenSSL,
    # log4j) are resolved through NVD's CPE Dictionary on the fly -- see
    # _resolve_banner_token. Cached session-wide so re-runs are free.
    candidates = _build_cpe_candidates(
        cpe_list or [], product, version,
        extra_info=extra_info, script_outputs=script_outputs,
    )

    # Cache key. Multi-candidate services pin to the full sorted candidate
    # list so re-runs with the same nmap data hit cache, but a service that
    # gains an extra sub-product (e.g. operator added http-server-header to
    # the scan) doesn't read a stale empty list from before. The host's OS
    # family is appended so strict-eval rejection (Apache mod_isapi on a
    # Linux host vs Windows host) doesn't share a cache slot between
    # platforms that get different filter results.
    os_family = _normalize_os_family(host_os_cpe)
    if candidates:
        cache_key = "+".join(sorted(candidates)) + f"|os={os_family}"
    else:
        cache_key = f"kw:{product.lower().strip()}:{(version or '').lower().strip()}|os={os_family}"

    cached = cache.get(cache_key)
    if cached is not None:
        return EnrichmentResult(product=product, version=version or "", cves=cached, from_cache=True)

    # Query NVD per candidate, union by CVE ID. NvdTransientError bubbles
    # up from _execute_nvd_query when NVD is unreachable after retries --
    # we refuse to cache that outcome (an empty list from a failed query
    # would silently hide real CVEs for a week). Every other outcome
    # (including a legitimate empty result) is authoritative and gets cached.
    cves: list[CVEInfo] = []
    try:
        if candidates:
            unioned: dict[str, CVEInfo] = {}
            for cpe23 in candidates:
                cpe_result = _query_nvd_cpe(
                    cpe23, service_version_override=version, host_os_cpe=host_os_cpe,
                )
                if cpe_result is None:
                    # NVD 404 on this CPE -- skip silently. Other candidates
                    # may still resolve. We try keyword fallback only when
                    # every candidate came back 404 or empty (handled below).
                    continue
                if not cpe_result and _has_specific_version(cpe23):
                    # Vendor pinned CVEs to major version only (esxi:8.0 vs
                    # esxi:8.0.3). Retry once with version wildcarded; the
                    # service_version_override keeps the applicability filter
                    # honest -- see _query_nvd_cpe docstring.
                    relaxed = _relax_cpe_version(cpe23)
                    if relaxed and relaxed != cpe23:
                        cpe_result = _query_nvd_cpe(
                            relaxed, service_version_override=version, host_os_cpe=host_os_cpe,
                        ) or []
                for cve in cpe_result:
                    if cve.cve_id not in unioned:
                        unioned[cve.cve_id] = cve
            cves = list(unioned.values())

            # Keyword fallback only when zero candidates produced anything.
            # When at least one candidate returned CVEs, suppress the noisy
            # keyword pass -- it would re-find the same gold and add product
            # noise via keyword matching on the verbose compound product.
            if not cves:
                clean_ver = _extract_version(version)
                logger.info(
                    "All %d CPE candidates returned empty for %s, trying keyword %s %s",
                    len(candidates), product, product, clean_ver,
                )
                cves = _query_nvd_keyword(product, clean_ver, host_os_cpe=host_os_cpe)
        elif version:
            clean_ver = _extract_version(version)
            if clean_ver != "*":
                cves = _query_nvd_keyword(product, clean_ver, host_os_cpe=host_os_cpe)
            else:
                return EnrichmentResult(product=product, version=version or "", error="No parseable version")
        else:
            # No CPE and no version -- skip (too noisy)
            return EnrichmentResult(product=product, version="", error="No CPE and no version")
    except NvdTransientError as e:
        # NVD failed transiently -- skip without caching. Next run will
        # retry with a clean slate instead of reading a poisoned empty
        # result out of the 7-day cache.
        logger.warning("NVD transient failure for %s %s: %s", product, version or "", e)
        return EnrichmentResult(
            product=product,
            version=version or "",
            error=f"NVD transient failure: {e}",
        )

    # Cache only authoritative NVD answers (including legitimate zero-CVE
    # responses). Transient failures already returned above without touching
    # the cache.
    cache.put(cache_key, cves)

    return EnrichmentResult(product=product, version=version or "", cves=cves)


def enrich_services_from_graph(
    progress_callback=None,
) -> dict:
    """Enrich all services in the Neo4j graph with CVE data.

    Reads services with CPE or product+version, queries NVD API,
    creates Vulnerability nodes and HAS_VULN relationships.

    Args:
        progress_callback: Optional callable(current, total, message) invoked
            after each service is processed. Used to report progress from a
            background analysis job.

    Returns:
        Dict with enrichment statistics.
    """
    from cauldron.graph.connection import get_session

    stats = {
        "services_checked": 0,
        "services_with_cves": 0,
        "total_cves_found": 0,
        "from_cache": 0,
        "api_calls": 0,
        "errors": 0,
        "skipped": 0,
        "cpe_queries": 0,
        "keyword_queries": 0,
    }

    cache = CVECache()

    with get_session() as session:
        # Get services with CPE or product info that have no NVD CVEs yet.
        # Services with only exploit_db/ai CVEs still get NVD enrichment.
        #
        # extra_info and script_* properties are pulled too -- the candidate
        # builder tokenizes them for sub-product CPE resolution (mod_ssl,
        # OpenSSL, log4j tucked inside compound banners and script outputs).
        # Script outputs are stored as svc.script_<id> properties by
        # _upsert_script_result, so we project them via [k IN keys(s) ...].
        #
        # host_ip / port / protocol come along so we can link CVEs back to
        # the exact services that produced each candidate set -- the
        # product+version fallback fails for services whose product is a
        # compound banner and version is null (Apache+mod_ssl+OpenSSL on
        # :443 in nmap's output).
        result = session.run(
            """
            MATCH (h:Host)-[:HAS_SERVICE]->(s:Service)
            WHERE (s.cpe IS NOT NULL OR s.product IS NOT NULL)
            AND NOT (s)-[:HAS_VULN]->(:Vulnerability {source: 'nvd'})
            RETURN
                h.ip AS host_ip,
                h.os_cpe AS host_os_cpe,
                h.os_accuracy AS host_os_accuracy,
                s.port AS port,
                s.protocol AS protocol,
                s.product AS product,
                s.version AS version,
                s.cpe AS cpe,
                s.extra_info AS extra_info,
                [k IN keys(s) WHERE k STARTS WITH 'script_' | s[k]] AS script_outputs
            """
        )

        # Strict configuration-tree eval only fires when the host's OS is
        # confirmed at 100% accuracy — smb-os-discovery (protocol-level
        # truth) or nmap -O on a stack clear enough to return an exact
        # match. Anything below that is a guess (nmap routinely returns
        # "Linux 89% / BSD 87%" on ambiguous stacks); passing such a
        # guess through to the AND-config rejector would FALSE-REJECT
        # legitimate CVEs when nmap misidentified the family. ``None``
        # for host_os_cpe at strict-eval time means "defer" — the
        # existing version-range filter handles those hosts as before.
        services = [
            (
                r["host_ip"],
                r["host_os_cpe"] if r["host_os_accuracy"] == 100 else None,
                r["port"], r["protocol"],
                r["product"], r["version"], r["cpe"],
                r["extra_info"], r["script_outputs"] or [],
            )
            for r in result
        ]

    # Group services by their candidate set. Services with identical
    # candidates share one NVD enrichment pass; the resulting CVEs link to
    # every endpoint in the group. The key now reflects the full CPE
    # candidate list (including resolved sub-products), so two services
    # with the same primary CPE but different sub-products (mod_ssl on
    # one, not on the other) get separate NVD passes.
    # Normalize host OS CPE to a coarse family ('linux' / 'windows' / 'macos'
    # / 'unknown'). The strict configuration-tree filter only needs the OS
    # family to evaluate AND-config platform contexts — splitting at major-
    # version granularity would explode cache cardinality without changing
    # the rejection outcome (an AND-config requiring Windows fails for any
    # Linux distro identically). Hosts with no os_cpe end up under
    # ``'unknown'``: the strict eval defers there, same as before.
    from collections import defaultdict
    groups: dict[str, dict] = defaultdict(lambda: {"endpoints": [], "rep": None})
    for (host_ip, host_os_cpe, port, protocol, product, version, cpe_str,
         extra_info, script_outputs) in services:
        cpe_list = cpe_str.split(";") if cpe_str else []
        candidates = _build_cpe_candidates(
            cpe_list, product, version, extra_info=extra_info, script_outputs=script_outputs,
        )
        os_family = _normalize_os_family(host_os_cpe)
        if candidates:
            key = "+".join(sorted(candidates)) + f"|os={os_family}"
        else:
            key = f"kw:{(product or '').lower()}:{(version or '').lower()}|os={os_family}"
        groups[key]["endpoints"].append((host_ip, port, protocol))
        if groups[key]["rep"] is None:
            groups[key]["rep"] = (product, version, cpe_list, extra_info, script_outputs, host_os_cpe)

    unique_services = [
        (g["rep"][0], g["rep"][1], g["rep"][2], g["rep"][3], g["rep"][4], g["rep"][5], g["endpoints"])
        for g in groups.values()
    ]

    logger.info(
        "Found %d unique services to enrich (%d total before dedup)",
        len(unique_services),
        len(services),
    )

    total = len(unique_services)
    for idx, (product, version, cpe_list, extra_info, script_outputs, host_os_cpe, endpoints) in enumerate(unique_services, 1):
        stats["services_checked"] += 1
        if progress_callback:
            label = f"{product or '?'}{(' ' + version) if version else ''}"
            try:
                progress_callback(idx, total, f"NVD: {label}")
            except Exception:  # noqa: BLE001
                pass
        enrichment = enrich_service(
            product or "", version or "", cache, cpe_list,
            extra_info=extra_info, script_outputs=script_outputs,
            host_os_cpe=host_os_cpe,
        )

        if enrichment.error:
            # "No CPE and no version" / "Missing product" — not real errors,
            # just services we don't have enough data to query
            if "No CPE" in enrichment.error or "Missing product" in enrichment.error:
                stats["skipped"] = stats.get("skipped", 0) + 1
            else:
                stats["errors"] += 1
            continue

        if enrichment.from_cache:
            stats["from_cache"] += 1
        else:
            stats["api_calls"] += 1
            # Track query type. Any resolved candidate counts as a CPE query;
            # the keyword path only fires when zero candidates produced CVEs.
            candidates = _build_cpe_candidates(
                cpe_list, product, version,
                extra_info=extra_info, script_outputs=script_outputs,
            )
            if candidates:
                stats["cpe_queries"] += 1
            else:
                stats["keyword_queries"] += 1

        if enrichment.cves:
            stats["services_with_cves"] += 1
            stats["total_cves_found"] += len(enrichment.cves)

            # Write CVEs to Neo4j -- link to the exact (host, port) tuples
            # that produced this candidate set. Direct linking via
            # target_endpoints because the product+version / CPE-prefix
            # fallback fails for compound-banner services (Apache+mod_ssl
            # on :443 in nmap output).
            with get_session() as session:
                for cve in enrichment.cves:
                    _upsert_vulnerability(
                        session, product or "", version or "", cpe_list, cve,
                        target_endpoints=endpoints,
                    )

    # Defensive orphan sweep. The MERGE-after-MATCH refactor in
    # _upsert_vulnerability stops the function from creating dangling
    # :Vulnerability nodes when no service matches the link query, but
    # legacy data from earlier Cauldron versions (or any future code
    # path that resurrects the older pattern) can still leave hangers
    # behind. Running the sweep at the end of every NVD pass keeps the
    # graph consistent with /api/v1/stats — ``MATCH (v:Vulnerability)``
    # always equals "Vulnerabilities reachable from a Service."
    with get_session() as session:
        # Sweep keeps a Vulnerability alive if EITHER a Service or a
        # Host still points at it — the host-OS enricher creates
        # ``(:Host)-[:HAS_VULN]->(v)`` edges (kernel privesc CVEs that
        # don't anchor to any single service), so the Service-only
        # check would treat those as orphans and delete them.
        removed = session.run(
            """
            MATCH (v:Vulnerability)
            WHERE NOT EXISTS { (:Service)-[:HAS_VULN]->(v) }
              AND NOT EXISTS { (:Host)-[:HAS_VULN]->(v) }
            DETACH DELETE v
            RETURN count(v) AS removed
            """
        ).single()
    stats["orphans_removed"] = removed["removed"] if removed else 0
    if stats["orphans_removed"]:
        logger.info("Removed %d orphan Vulnerability nodes", stats["orphans_removed"])

    return stats


def _filter_host_os_cves_by_ownership(
    cves: list[CVEInfo], host_is_owned: bool,
) -> tuple[list[CVEInfo], int]:
    """Apply the AV:L gate at host-OS upsert time.

    AV:L kernel-privesc CVEs only become actionable after the operator
    has shell on the box — pre-foothold they sit in every host detail
    panel as dead weight competing with AV:N attack-surface findings.
    Mark-as-Owned is the event that should flip them into the graph;
    until then we skip the upsert for AV:L on un-owned hosts.

    The cache (``CVECache`` keyed by CPE) keeps the full result set —
    AV:L entries are NOT dropped at cache-write time. When the host
    later flips to owned, the Mark-as-Owned trigger (v0.2.0 piece B)
    re-runs this filter with ``host_is_owned=True`` and the cached
    AV:L entries flow through the upsert without a fresh NVD round-trip.

    Returns:
        (kept, av_l_skipped_count) — list of CVEs to upsert plus the
        count of AV:L entries the ownership gate dropped (for stats).
    """
    if host_is_owned:
        return cves, 0
    kept: list[CVEInfo] = []
    skipped = 0
    for cve in cves:
        if _cve_is_av_local(cve):
            skipped += 1
            continue
        kept.append(cve)
    return kept, skipped


def enrich_host_os_from_graph(progress_callback=None) -> dict:
    """Enrich Host nodes with OS-level CVE findings via NVD.

    Mirrors ``enrich_services_from_graph`` but operates on Host nodes
    instead of Service nodes, using ``h.os_cpe`` (sourced from nmap's
    ``<osclass><cpe>`` element or smb-os-discovery when available)
    instead of ``s.cpe``. Surfaces OS-attributed CVEs that the
    service-level pipeline can't reach — most importantly the Linux
    kernel privesc backlog (CVE-2009-2698 sock_sendpage,
    CVE-2010-3904 RDS, CVE-2009-2692 vmsplice) that's the canonical
    post-foothold escalation path on legacy targets.

    Three-stage architecture (cache as source of truth):

    1. **NVD query, once per unique OS CPE.** ``_query_nvd_cpe(cpe,
       host_os=True)`` keeps both AV:L and AV:N — only AV:P / DoS /
       PR:H / non-exploit get dropped. All results land in
       ``CVECache`` keyed by the CPE string. A 500-host engagement
       with ~10 distinct OS CPEs only ever hits NVD ~10 times.
    2. **Per-host upsert decision.** For each host with ``os_cpe``,
       read the cache and apply the AV:L-by-ownership gate
       (``_filter_host_os_cves_by_ownership``). AV:N OS CVEs
       (MS17-010, BlueKeep, SMBGhost) land on every host — external
       attack surface, ownership-independent. AV:L kernel privesc
       only lands on hosts already marked owned.
    3. **Mark-as-Owned re-enrichment** (v0.2.0 piece B, not in this
       commit) reads from the same cache, applies the filter with
       ``host_is_owned=True``, and writes the previously-skipped AV:L
       edges without any NVD round-trip.

    Findings attach to the Host via ``(:Host)-[:HAS_VULN]->(:Vulnerability)``
    rather than a Service. Downstream API merges service-level and
    host-level vulns on a single host detail response; the UI renders
    host-level rows with an ``OS`` badge instead of a port label.
    """
    from cauldron.graph.connection import get_session

    stats = {
        "hosts_checked": 0,
        "hosts_with_cves": 0,
        "total_cves_found": 0,
        "from_cache": 0,
        "api_calls": 0,
        "errors": 0,
        "skipped": 0,
        # Per-host AV:L-by-ownership gate stats — visibility on noise
        # the ownership filter removed from the upsert path.
        "av_l_skipped": 0,
        "av_l_skipped_hosts": 0,
    }

    cache = CVECache()

    with get_session() as session:
        # Host-OS NVD enrichment requires the OS identification to be
        # protocol-level certain. ``smb-os-discovery`` sets accuracy=100
        # because it reads the OS string directly from the SMB protocol;
        # nmap -O returns 100 only when its TCP/IP fingerprint matches a
        # single signature unambiguously. Anything below that is a guess
        # (a "Linux 89% / BSD 87%" osmatch) — querying NVD for kernel
        # CVEs against a CPE that might be wrong would attach a whole
        # branch of platform-specific findings to a host that doesn't
        # actually run that OS. We'd rather skip the host-OS pass than
        # pollute the graph with mis-attributed kernel privesc CVEs.
        # Hosts without accuracy=100 just don't get the OS-level CVE
        # pass; service-level enrichment still runs from the service
        # CPE list and is unaffected.
        hosts = list(session.run(
            """
            MATCH (h:Host)
            WHERE h.os_cpe IS NOT NULL AND h.os_accuracy = 100
            RETURN h.ip AS ip, h.os_cpe AS os_cpe, h.os_name AS os_name,
                   coalesce(h.os_cpe_alts, []) AS os_cpe_alts,
                   coalesce(h.owned, false) AS owned
            ORDER BY h.ip
            """,
        ))

    total = len(hosts)
    for idx, record in enumerate(hosts):
        ip = record["ip"]
        cpe22 = record["os_cpe"]
        host_is_owned = bool(record["owned"])
        cpe23 = _cpe22_to_23(cpe22)
        if not cpe23:
            # OS family not in ``_OS_CPE_PRODUCTS`` / Windows allowlist
            # (e.g. macOS, FreeBSD, generic ``cpe:/o:microsoft:windows``
            # without a major-version suffix). Skip rather than dump a
            # noisy "unrecognised CPE" log line per host.
            stats["skipped"] += 1
            continue

        # Alternative OS CPE anchors derived by the parser from
        # ``<osmatch name>`` (specific kernel versions when osclass is
        # generation-only). NVD virtualMatchString matches asymmetrically
        # against config-tree version ranges, so querying just the
        # generation-only CPE silently misses CVEs pinned with
        # versionStart/End markers. Each alt is queried in addition to
        # the primary CPE and the results merged.
        alt_cpe22s = list(record.get("os_cpe_alts") or [])
        alt_cpe23s = []
        for alt22 in alt_cpe22s:
            alt23 = _cpe22_to_23(alt22)
            if alt23 and alt23 != cpe23 and alt23 not in alt_cpe23s:
                alt_cpe23s.append(alt23)

        stats["hosts_checked"] += 1

        # Fetch the primary CPE plus each alt anchor, merging into one
        # de-duplicated CVE set per host. Each CPE has its own cache
        # entry so warm runs only pay the dedup cost.
        merged: dict[str, CVEInfo] = {}
        any_transient = False
        for query_cpe in [cpe23, *alt_cpe23s]:
            cached = cache.get(query_cpe)
            if cached is not None:
                fetched_list: list[CVEInfo] = list(cached)
                stats["from_cache"] += 1
            else:
                try:
                    fetched = _query_nvd_cpe(query_cpe, host_os=True)
                except NvdTransientError as e:
                    logger.warning(
                        "Host-OS NVD failure for %s (%s): %s",
                        ip, query_cpe, e,
                    )
                    stats["errors"] += 1
                    any_transient = True
                    break
                fetched_list = list(fetched) if fetched is not None else []
                stats["api_calls"] += 1
                cache.put(query_cpe, fetched_list)
            for cve in fetched_list:
                merged.setdefault(cve.cve_id, cve)

        if any_transient:
            if progress_callback:
                progress_callback(idx + 1, total, f"{ip}: NVD error")
            continue

        cves = list(merged.values())

        # Per-host AV:L ownership gate. Cache always carries the full
        # AV:L+AV:N result for the CPE; the filter happens here at
        # upsert time so a single NVD-side fetch can serve both owned
        # and un-owned hosts that share an OS CPE.
        upsert_cves, av_l_skipped = _filter_host_os_cves_by_ownership(
            cves, host_is_owned=host_is_owned,
        )
        if av_l_skipped > 0:
            stats["av_l_skipped"] += av_l_skipped
            stats["av_l_skipped_hosts"] += 1

        if not upsert_cves:
            if progress_callback:
                msg = f"{ip}: 0 CVEs"
                if av_l_skipped > 0:
                    msg += f" ({av_l_skipped} AV:L gated by ownership)"
                progress_callback(idx + 1, total, msg)
            continue

        stats["hosts_with_cves"] += 1
        stats["total_cves_found"] += len(upsert_cves)

        with get_session() as session:
            for cve in upsert_cves:
                _upsert_host_vulnerability(session, ip, cve)

        if progress_callback:
            msg = f"{ip}: {len(upsert_cves)} CVEs"
            if av_l_skipped > 0:
                msg += f" (+{av_l_skipped} AV:L gated by ownership)"
            progress_callback(idx + 1, total, msg)

    return stats


def reenrich_host_os_on_ownership(ip: str, owned: bool) -> dict:
    """Re-enrich a single host's host-OS findings after a Mark-as-Owned flip.

    Reads from ``CVECache`` only — no NVD round-trip. The cache holds the
    full AV:L + AV:N result set per OS CPE (see ``CVECache`` as the
    source-of-truth invariant); the per-host AV:L gate moved to upsert
    time in piece A so this trigger can flow previously-skipped kernel-
    privesc edges through without re-querying NVD.

    Behaviour:
      - ``owned=True`` — apply the ownership-aware filter with
        ``host_is_owned=True`` and upsert every AV:L entry in cache. AV:N
        entries are already attached from the initial enrichment pass;
        only AV:L is new on the ownership flip.
      - ``owned=False`` — purge every AV:L host-OS edge from this host.
        AV:N edges (external attack surface) stay; orphan vulnerabilities
        that lose their last edge get reaped on the next ``boil``.

    Args:
        ip: Host IP to re-enrich.
        owned: New ownership state (already written to ``h.owned`` by the
            caller — this function only handles the CVE-edge side).

    Returns:
        Stats dict with keys ``ip``, ``owned``, ``av_l_added``,
        ``av_l_removed``, ``cache_miss``, ``no_os_cpe``, ``host_missing``.
        Designed for FastAPI ``BackgroundTask`` use — exceptions are
        caught and logged so a re-enrichment failure cannot break the
        ownership PATCH that triggered it.
    """
    from cauldron.graph.connection import get_session

    stats = {
        "ip": ip,
        "owned": owned,
        "av_l_added": 0,
        "av_l_removed": 0,
        "cache_miss": False,
        "no_os_cpe": False,
        "host_missing": False,
        # New: re-enrichment was skipped because the host's OS was not
        # 100%-confirmed. Mirrors the same gate as ``enrich_host_os_from_graph``
        # so Mark-as-Owned can never add AV:L kernel-privesc CVEs based
        # on a low-confidence OS guess.
        "low_os_confidence": False,
    }

    try:
        with get_session() as session:
            record = session.run(
                "MATCH (h:Host {ip: $ip}) "
                "RETURN h.os_cpe AS os_cpe, h.os_accuracy AS os_accuracy",
                ip=ip,
            ).single()

        if record is None:
            stats["host_missing"] = True
            logger.warning("Mark-as-Owned re-enrichment: host %s not found", ip)
            return stats

        cpe22 = record.get("os_cpe")
        os_accuracy = record.get("os_accuracy")

        if not owned:
            # Un-own — purge AV:L host-OS edges. AV:N stays; the next
            # boil's orphan sweep handles any Vulnerability that loses
            # its last edge. We delete unconditionally regardless of
            # OS-accuracy: if a previous boil DID populate AV:L (back
            # when the host was owned with high-confidence OS), un-
            # owning should still clean them up. The gate only blocks
            # writing new edges, not purging existing ones.
            with get_session() as session:
                result = session.run(
                    """
                    MATCH (h:Host {ip: $ip})-[r:HAS_VULN]->(v:Vulnerability)
                    WHERE v.cvss_vector CONTAINS 'AV:L'
                    DELETE r
                    RETURN count(r) AS removed
                    """,
                    ip=ip,
                )
                rec = result.single()
                stats["av_l_removed"] = rec["removed"] if rec else 0
            logger.info(
                "Mark-as-Owned re-enrichment (unowned): %s — removed %d AV:L edges",
                ip, stats["av_l_removed"],
            )
            return stats

        # owned=True — read cache and upsert AV:L entries
        if not cpe22:
            stats["no_os_cpe"] = True
            logger.info(
                "Mark-as-Owned re-enrichment: %s has no os_cpe — nothing to add. "
                "Run `cauldron boil --nvd` after a scan with OS fingerprinting.",
                ip,
            )
            return stats

        # OS-accuracy gate. ``enrich_host_os_from_graph`` only populates
        # the host-OS CVE cache for hosts with 100%-confirmed OS; running
        # Mark-as-Owned re-enrichment on a low-confidence host either
        # finds no cache (cache_miss) or worse, finds a cache populated
        # under a different host's high-confidence OS CPE (cache is
        # keyed by CPE, not by host). Block early either way — we never
        # want Mark-as-Owned to add AV:L kernel privesc CVEs based on a
        # guessed OS.
        if os_accuracy != 100:
            stats["low_os_confidence"] = True
            logger.info(
                "Mark-as-Owned re-enrichment: %s has os_accuracy=%s (< 100). "
                "Re-run nmap with -O against this host for protocol-level OS "
                "confirmation, then re-mark to enrich kernel privesc CVEs.",
                ip, os_accuracy,
            )
            return stats

        cpe23 = _cpe22_to_23(cpe22)
        if not cpe23:
            stats["no_os_cpe"] = True
            return stats

        cache = CVECache()
        cached = cache.get(cpe23)
        if cached is None:
            stats["cache_miss"] = True
            logger.warning(
                "Mark-as-Owned re-enrichment: cache cold for %s (%s) — "
                "run `cauldron boil --nvd` to populate, then re-mark.",
                ip, cpe23,
            )
            return stats

        av_l_cves = [c for c in cached if _cve_is_av_local(c)]
        if not av_l_cves:
            logger.info(
                "Mark-as-Owned re-enrichment: %s — cache has %d CVEs, "
                "none AV:L (no kernel privesc to add).",
                ip, len(cached),
            )
            return stats

        with get_session() as session:
            for cve in av_l_cves:
                _upsert_host_vulnerability(session, ip, cve)

        stats["av_l_added"] = len(av_l_cves)
        logger.info(
            "Mark-as-Owned re-enrichment: %s — upserted %d AV:L edges from cache",
            ip, stats["av_l_added"],
        )
        return stats
    except Exception:  # noqa: BLE001
        # Background-task contract: never raise out of this function. The
        # ownership PATCH already succeeded server-side; logging is the
        # only feedback channel for re-enrichment failures.
        logger.exception("Mark-as-Owned re-enrichment failed for %s", ip)
        return stats


def _fetch_epss_batch(cve_ids: list[str]) -> dict[str, float]:
    """Query FIRST.org for EPSS scores in a single batch request.

    Returns a {cve_id: epss_score} dict. CVEs missing from the response
    (unknown to EPSS) are simply absent from the dict — callers treat
    that as "no EPSS data" and leave ``v.epss`` null on the graph.

    Transient failures return an empty dict and log a warning; the next
    boil retries. We do not raise NvdTransientError here because EPSS
    is a nice-to-have signal — a temporary FIRST.org outage must not
    break the entire boil pipeline the way NVD would.
    """
    # Drop anything not in strict MITRE format before building the URL —
    # the graph may have garbage synthetic IDs that slipped through the
    # ``STARTS WITH 'CVE-'`` Cypher filter (``CVE-foo`` etc.).
    valid = [c for c in cve_ids if _CVE_ID_RE.match(c)]
    if not valid:
        return {}

    cve_param = ",".join(valid)
    url = f"{EPSS_API_BASE}?cve={cve_param}"
    req = urllib.request.Request(url, headers={"User-Agent": "Cauldron/0.1.0"})

    try:
        resp = urllib.request.urlopen(req, timeout=_NVD_REQUEST_TIMEOUT)
        data = json.loads(resp.read())
    except (urllib.error.HTTPError, urllib.error.URLError,
            OSError, json.JSONDecodeError) as e:
        logger.warning("EPSS fetch failed for %d CVEs: %s", len(cve_ids), e)
        return {}

    scores: dict[str, float] = {}
    for entry in data.get("data", []):
        cve_id = entry.get("cve")
        raw = entry.get("epss")
        if not cve_id or raw is None:
            continue
        try:
            scores[cve_id] = float(raw)
        except (TypeError, ValueError):
            continue
    return scores


def enrich_epss_from_graph(progress_callback=None) -> dict:
    """Populate ``v.epss`` on every Vulnerability node that still lacks it.

    Pulls CVE-format IDs from the graph, consults the 24h EPSS cache
    first, batches remaining IDs to FIRST.org in chunks of
    ``_EPSS_BATCH_SIZE``, and writes the scores back. Non-CVE synthetic
    IDs (``CAULDRON-*``) are skipped — FIRST.org only scores real CVEs.

    Returns:
        Dict with {checked, from_cache, fetched, updated, missing}.
    """
    from cauldron.graph.connection import get_session

    stats = {
        "checked": 0,
        "from_cache": 0,
        "fetched": 0,
        "updated": 0,
        "missing": 0,
    }

    with get_session() as session:
        rows = list(session.run(
            """
            MATCH (v:Vulnerability)
            WHERE v.cve_id STARTS WITH 'CVE-' AND v.epss IS NULL
            RETURN v.cve_id AS cve_id
            """,
        ))

    cve_ids = [r["cve_id"] for r in rows]
    stats["checked"] = len(cve_ids)
    if not cve_ids:
        return stats

    cache = EPSSCache()
    scores: dict[str, float] = {}
    to_fetch: list[str] = []

    for cve_id in cve_ids:
        cached = cache.get(cve_id)
        if cached is not None:
            scores[cve_id] = cached
            stats["from_cache"] += 1
        else:
            to_fetch.append(cve_id)

    # Batch the rest to FIRST.org — one URL per _EPSS_BATCH_SIZE CVEs.
    total_batches = (len(to_fetch) + _EPSS_BATCH_SIZE - 1) // _EPSS_BATCH_SIZE
    for idx, start in enumerate(range(0, len(to_fetch), _EPSS_BATCH_SIZE), 1):
        batch = to_fetch[start : start + _EPSS_BATCH_SIZE]
        if progress_callback:
            try:
                progress_callback(idx, total_batches, f"EPSS batch {idx}/{total_batches}")
            except Exception:  # noqa: BLE001
                pass
        fetched = _fetch_epss_batch(batch)
        stats["fetched"] += len(fetched)
        if fetched:
            cache.put_batch(fetched)
            scores.update(fetched)

    stats["missing"] = len(cve_ids) - len(scores)

    # Write back to Neo4j in one batched query — UNWIND a pairs list so
    # the driver does not pay a round-trip per CVE.
    if scores:
        pairs = [{"cve_id": cid, "epss": epss} for cid, epss in scores.items()]
        with get_session() as session:
            session.run(
                """
                UNWIND $pairs AS p
                MATCH (v:Vulnerability {cve_id: p.cve_id})
                SET v.epss = p.epss
                """,
                pairs=pairs,
            )
        stats["updated"] = len(scores)

    logger.info(
        "EPSS enrichment: %d CVEs checked (%d cached, %d fetched, %d missing)",
        stats["checked"], stats["from_cache"], stats["fetched"], stats["missing"],
    )
    return stats


_VULN_MERGE_CLAUSE = """
    MERGE (v:Vulnerability {cve_id: $cve_id})
    ON CREATE SET
        v.cvss = $cvss,
        v.cvss_vector = $cvss_vector,
        v.severity = $severity,
        v.description = $description,
        v.has_exploit = $has_exploit,
        v.exploit_url = $exploit_url,
        v.exploit_sources = $exploit_sources,
        v.epss = $epss,
        v.in_cisa_kev = $in_cisa_kev,
        v.cisa_kev_added = $cisa_kev_added,
        v.source = 'nvd'
    ON MATCH SET
        v.cvss = COALESCE($cvss, v.cvss),
        v.cvss_vector = COALESCE($cvss_vector, v.cvss_vector),
        v.severity = COALESCE($severity, v.severity),
        v.has_exploit = CASE WHEN $has_exploit THEN true ELSE v.has_exploit END,
        v.exploit_url = COALESCE($exploit_url, v.exploit_url),
        v.exploit_sources = CASE
            WHEN $exploit_sources IS NULL OR $exploit_sources = '' THEN v.exploit_sources
            WHEN v.exploit_sources IS NULL OR v.exploit_sources = '' THEN $exploit_sources
            WHEN v.exploit_sources = $exploit_sources THEN v.exploit_sources
            ELSE v.exploit_sources + '+' + $exploit_sources
        END,
        v.epss = COALESCE($epss, v.epss),
        v.in_cisa_kev = CASE WHEN $in_cisa_kev THEN true ELSE v.in_cisa_kev END,
        v.cisa_kev_added = COALESCE($cisa_kev_added, v.cisa_kev_added),
        v.source = CASE
            WHEN v.source IS NULL THEN 'nvd'
            WHEN v.source = 'nvd' THEN 'nvd'
            WHEN v.source CONTAINS 'nvd' THEN v.source
            ELSE v.source + '+nvd'
        END
"""


def _upsert_host_vulnerability(session, host_ip: str, cve: CVEInfo) -> None:
    """Link a CVE to a Host node via ``HAS_VULN``.

    Mirror of ``_upsert_vulnerability``'s target-endpoint path, but
    keyed on the Host rather than a specific Service. Used by the
    host-OS enricher to attach OS-attributed bugs (kernel privesc,
    OS-wide RCEs) that don't anchor to any single port.

    The Vulnerability MERGE shares ``_VULN_MERGE_CLAUSE`` with the
    service path so multi-source handling, EPSS / KEV backfills, and
    ``v.source = '…+nvd'`` semantics all behave identically — the
    only difference is the relationship endpoint.

    Orphan-prevention contract holds: the Vulnerability MERGE is
    gated behind ``MATCH (h:Host)`` in the same statement. If the
    host vanishes between the enricher's read pass and the upsert,
    nothing dangles.
    """
    version_unconfirmed = not getattr(cve, "matched_version_pinned", False)
    cve_params = {
        "cve_id": cve.cve_id,
        "cvss": cve.cvss,
        "cvss_vector": cve.cvss_vector,
        "severity": cve.severity,
        "description": cve.description,
        "has_exploit": cve.has_exploit,
        "exploit_url": cve.exploit_url,
        "exploit_sources": cve.exploit_sources or "",
        "epss": cve.epss,
        "in_cisa_kev": cve.in_cisa_kev,
        "cisa_kev_added": cve.cisa_kev_added,
    }
    session.run(
        f"""
        MATCH (h:Host {{ip: $ip}})
        {_VULN_MERGE_CLAUSE}
        MERGE (h)-[rel:HAS_VULN]->(v)
        ON CREATE SET rel.confidence = 'check'
        SET rel.version_unconfirmed = $version_unconfirmed
        """,
        ip=host_ip,
        version_unconfirmed=version_unconfirmed,
        **cve_params,
    )


def _upsert_vulnerability(
    session,
    product: str,
    version: str,
    cpe_list: list[str],
    cve: CVEInfo,
    target_endpoints: list[tuple[str, int, str]] | None = None,
) -> None:
    """Create/update Vulnerability node and link to matching services.

    Confidence lives on the HAS_VULN relationship, not on the node — a
    script-confirmed upgrade on one host must not leak "confirmed" onto
    every other host sharing the same CVE ID. Default for NVD-sourced
    findings is 'check'; script_upgrades or AI triage can lift a
    specific edge to 'likely' / 'confirmed' independently.

    Linking strategy:
      * If ``target_endpoints`` is provided (list of (ip, port, protocol)
        tuples), link only to those exact services. Used by the multi-CPE
        candidate enricher, where the caller already knows which services
        produced each candidate set.
      * Otherwise fall back to matching services by product+version and by
        CPE prefix. Kept for backward compatibility with callers that
        don't have explicit endpoint info.

    Orphan-prevention contract: the Vulnerability node is MERGE-d
    inside the same Cypher statement that MATCHes the target Service.
    If the service MATCH fails (or yields zero services on the legacy
    fallback paths), the rest of the query — including the Vulnerability
    MERGE — never executes. The graph never accumulates a
    ``:Vulnerability`` node that has no HAS_VULN edge attached to it.
    """
    # Per-edge ``version_unconfirmed`` — True when the CPE that produced
    # this CVE did NOT carry a pinned version (and no service-version
    # override was threaded in). For sub-product matches (e.g. mod_ssl
    # 2.8.4 on an Apache service that itself lacks a version in
    # ``s.version``), the CPE version IS pinned, so the edge correctly
    # reports the finding as version-confirmed despite the host-level
    # ambiguity. Legacy keyword-fallback CVEs and old data without this
    # property fall back to the service-level check in the API Cypher.
    version_unconfirmed = not getattr(cve, "matched_version_pinned", False)

    cve_params = {
        "cve_id": cve.cve_id,
        "cvss": cve.cvss,
        "cvss_vector": cve.cvss_vector,
        "severity": cve.severity,
        "description": cve.description,
        "has_exploit": cve.has_exploit,
        "exploit_url": cve.exploit_url,
        "exploit_sources": cve.exploit_sources or "",
        "epss": cve.epss,
        "in_cisa_kev": cve.in_cisa_kev,
        "cisa_kev_added": cve.cisa_kev_added,
    }

    # Direct endpoint linking -- caller knows exactly which services to
    # attach this CVE to (multi-CPE candidate path). The Service MATCH
    # gates the Vulnerability MERGE in one statement, so a stale
    # endpoint that no longer resolves to a Service never produces an
    # orphan Vulnerability node.
    if target_endpoints:
        for ip, port, protocol in target_endpoints:
            session.run(
                f"""
                MATCH (s:Service {{host_ip: $ip, port: $port, protocol: $protocol}})
                {_VULN_MERGE_CLAUSE}
                MERGE (s)-[rel:HAS_VULN]->(v)
                ON CREATE SET rel.confidence = 'check'
                SET rel.version_unconfirmed = $version_unconfirmed
                """,
                ip=ip, port=port, protocol=protocol,
                version_unconfirmed=version_unconfirmed,
                **cve_params,
            )
        return

    # Legacy fallback: link by product+version. ``WITH collect(...) AS
    # svcs WHERE size(svcs) > 0`` short-circuits the query when no
    # services match — without this guard the MERGE (v:Vulnerability)
    # below would fire even with zero candidates and leave a dangling
    # node behind.
    if product and version:
        session.run(
            f"""
            MATCH (s:Service)
            WHERE s.product = $product AND s.version = $version
            WITH collect(s) AS svcs
            WHERE size(svcs) > 0
            {_VULN_MERGE_CLAUSE}
            WITH v, svcs
            UNWIND svcs AS s
            MERGE (s)-[rel:HAS_VULN]->(v)
            ON CREATE SET rel.confidence = 'check'
            SET rel.version_unconfirmed = $version_unconfirmed
            """,
            product=product,
            version=version,
            version_unconfirmed=version_unconfirmed,
            **cve_params,
        )

    # Also link by CPE (catches services where product name differs but CPE matches).
    #
    # The part type (a/o/h) must come from the converted CPE 2.3 — NOT
    # hardcoded. ``cpe:/o:vmware:esxi:7.0.3`` stays on the Service as a
    # ``cpe:/o:...`` URI, so building a ``cpe:/a:...`` linking prefix
    # would silently skip every OS-typed host (ESXi, Cisco IOS,
    # RouterOS, PAN-OS, FortiOS). ``_cpe22_to_23`` already emits the
    # right part type for both the gated OS products and applications,
    # so we echo it straight back into the prefix.
    for cpe in cpe_list:
        cpe23 = _cpe22_to_23(cpe)
        if cpe23:
            parts = cpe23.split(":")
            if len(parts) >= 6:
                cpe_part = parts[2]  # 'a', 'o', or 'h' — preserved from input
                cpe_vendor = parts[3]
                cpe_product = parts[4]
                cpe_version = parts[5]
                if cpe_version and cpe_version != "*":
                    cpe_prefix = f"cpe:/{cpe_part}:{cpe_vendor}:{cpe_product}:{cpe_version}"
                else:
                    cpe_prefix = f"cpe:/{cpe_part}:{cpe_vendor}:{cpe_product}"
                session.run(
                    f"""
                    MATCH (s:Service)
                    WHERE s.cpe STARTS WITH $prefix OR s.cpe CONTAINS $contains
                    WITH collect(s) AS svcs
                    WHERE size(svcs) > 0
                    {_VULN_MERGE_CLAUSE}
                    WITH v, svcs
                    UNWIND svcs AS s
                    MERGE (s)-[rel:HAS_VULN]->(v)
                    ON CREATE SET rel.confidence = 'check'
                    SET rel.version_unconfirmed = $version_unconfirmed
                    """,
                    prefix=cpe_prefix,
                    contains=f";{cpe_prefix}",
                    version_unconfirmed=version_unconfirmed,
                    **cve_params,
                )
