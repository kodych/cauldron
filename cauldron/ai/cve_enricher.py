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
- CVSS v3.1/v3.0/v2 score extraction
- Version validation against CVE configurations
- Filters disputed/rejected CVEs
"""

from __future__ import annotations

import json
import logging
import re
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

# Cache location
CACHE_DIR = Path.home() / ".cauldron"
CACHE_FILE = CACHE_DIR / "cve_cache.json"

# Rate limiting: track last request time
_last_request_time: float = 0.0

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
    epss: float | None = None
    cwe_ids: list[str] = field(default_factory=list)
    published: str | None = None  # ISO date string from NVD
    # CISA Known Exploited Vulnerabilities catalog — True when CISA lists
    # the CVE as actively exploited in the wild (stronger signal than
    # has_exploit, which only means a PoC exists somewhere).
    in_cisa_kev: bool = False
    cisa_kev_added: str | None = None  # ISO date CISA added it

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


def _rate_limit() -> None:
    """Enforce NVD API rate limits."""
    global _last_request_time
    delay = 0.7 if settings.nvd_api_key else 6.5
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
# queries against them return zero matches. Network/appliance vendors that
# ship as integrated OS belong here.
_OS_CPE_PRODUCTS: set[str] = {
    "vmware:esxi",
    "cisco:ios",
    "cisco:ios_xe",
    "cisco:nxos",
    "paloaltonetworks:pan-os",
    "fortinet:fortios",
    "juniper:junos",
    "mikrotik:routeros",
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
        # Only convert OS CPEs for high-value targets with specific versions
        vendor_l = vendor.lower()
        product_l = product.lower()
        vp_key = f"{vendor_l}:{product_l}"
        if vp_key in _OS_CPE_PRODUCTS and version != "*":
            return f"cpe:2.3:o:{vendor_l}:{product_l}:{version}:*:*:*:*:*:*:*"

    return None


def _build_cpe23(vendor: str, product: str, version: str = "*") -> str:
    """Build a CPE 2.3 string from components.

    Picks the CPE part type (application ``a`` vs operating system ``o``) based
    on whether the vendor:product is in the OS-registered set. Products like
    ESXi, MikroTik RouterOS, PAN-OS, FortiOS, Cisco IOS are registered as
    ``o:`` in NVD — application-typed queries against them return zero matches.
    """
    vp_key = f"{vendor}:{product}".lower()
    part_type = "o" if vp_key in _OS_CPE_PRODUCTS else "a"
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
    1. Application/OS CPE from nmap (with vendor corrections)
    2. Fallback mapping from PRODUCT_CPE_MAP
    """
    # Try nmap's CPE output first
    for cpe in cpe_list:
        cpe23 = _cpe22_to_23(cpe)
        if cpe23:
            return cpe23

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


def _cve_is_gold(cve: CVEInfo, versionless: bool = False) -> bool:
    """Decide whether a CVE clears the "actionable gold" bar for a pentester.

    Single gate: a CVE must have a public exploit to count as gold. When we
    have a service version, ``_cve_applies_to`` upstream has already
    confirmed the CVE's version range covers it. When we do not, we assume
    the service runs the latest release — so we additionally drop exploits
    that target ancient releases only (``versionless`` path, recency cut).

    "Theoretical critical" CVEs (CVSS 9.x with no PoC) were the dominant
    noise pattern on real client scans: dozens of Apache/Samba CVEs
    bulk-attached to every host with no actionable follow-up. Requiring
    has_exploit cuts that entire class while preserving every CISA-KEV
    entry via the override below.

    Order (first matching wins):
      1. Hard rejects — AV:L/AV:P and pure-DoS drop even for KEV.
         CVE-2023-44487 (HTTP/2 Rapid Reset) is in CISA KEV but pure DoS.
      2. CISA-KEV soft override — actively exploited in the wild beats the
         has_exploit gate AND the versionless recency cut.
      3. Admin-required reject — PR:H CVEs are post-exploitation, not a way in.
      4. Versionless recency reject — for "assume latest" queries, drop
         exploits registered against releases too old to still be running.
      5. Actionable-exploit gate — has_exploit.
    """
    if _cve_is_local_only(cve):
        return False
    if _cve_is_dos_only(cve):
        return False

    if cve.in_cisa_kev:
        return True

    if _cve_requires_admin(cve):
        return False

    if versionless:
        year = _cve_published_year(cve)
        if year is not None and year < datetime.now(timezone.utc).year - _VERSIONLESS_RECENCY_YEARS:
            return False

    return cve.has_exploit


# --- NVD API queries ---

def _has_specific_version(cpe23: str) -> bool:
    """Check if CPE has a specific version (not wildcard)."""
    parts = cpe23.split(":")
    # cpe:2.3:a:vendor:product:VERSION:...
    return len(parts) >= 6 and parts[5] != "*"


def _query_nvd_cpe(cpe23: str, service_version_override: str | None = None) -> list[CVEInfo] | None:
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

    cves = _execute_nvd_query(
        url, f"CPE:{cpe23}",
        version_hint=version_hint,
        version_applies_product=applies_product,
    )

    # None = 404 (CPE not in NVD) — signal caller to try keyword fallback
    if cves is None:
        return None

    # Coarse pentester filter first (CWE + pattern), then the gold filter
    # requires an actionable public exploit (KEV overrides). Hard rejects
    # (local/DoS/admin-required) apply in both paths; the versionless path
    # also cuts CVEs published too long ago to plausibly affect "latest".
    cves = [c for c in cves if _is_pentester_relevant(c)]
    cves = [c for c in cves if _cve_is_gold(c, versionless=not has_version)]

    # Pentester-priority sort: CISA KEV (active in-the-wild exploitation)
    # first, then CVEs with a public exploit, then CVSS descending within
    # each tier. A low-CVSS CVE with a Metasploit module is more useful
    # than a high-CVSS theoretical one.
    cves.sort(key=_cve_priority_key)
    return cves[:20 if has_version else 50]


def _query_nvd_keyword(product: str, version: str) -> list[CVEInfo]:
    """Query NVD API using keywordSearch (fallback, less precise).

    Validates results against CVE's CPE configurations to ensure the CVE
    actually affects the target product, not just mentions it.

    NVD quirk: keywordSearch combined with pubStartDate returns HTTP 404,
    so date-restriction is not available server-side. With a versionless
    query we drop ``keywordExactMatch`` to allow vendor-only searches (e.g.
    "Veeam Backup" finding CVEs assigned to full "Veeam Backup & Replication"
    products); the pentester CWE filter + severity sort compensates.
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
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        # 403 = rate limit, 503 = service unavailable — both retryable
        if e.code in (403, 429, 500, 502, 503, 504) and _retries < 3:
            backoff = 15 * (2 ** _retries)  # 15s, 30s, 60s
            logger.warning(
                "NVD API error %d for %s. Retry %d/3, waiting %ds...",
                e.code, context, _retries + 1, backoff,
            )
            time.sleep(backoff)
            return _execute_nvd_query(
                url, context, product_hint, version_hint, version_applies_product, _retries + 1,
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
        if _retries < 3:
            backoff = 5 * (2 ** _retries)  # 5s, 10s, 20s
            logger.warning(
                "NVD API request failed for %s: %s. Retry %d/3, waiting %ds...",
                context, e, _retries + 1, backoff,
            )
            time.sleep(backoff)
            return _execute_nvd_query(
                url, context, product_hint, version_hint, version_applies_product, _retries + 1,
            )
        logger.error("NVD API request failed for %s after 3 retries: %s", context, e)
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
        if applies_product and not _cve_applies_to(cve_data, applies_product, version_hint):
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


def _cve_applies_to(cve_data: dict, product_lower: str, version: str | None) -> bool:
    """Validate that a CVE's CPE configuration actually covers our service.

    The NVD ``virtualMatchString`` endpoint is generous: it returns every CVE
    whose CPE configuration mentions the vendor:product, regardless of the
    version pinned in that configuration. When our service is versionless
    (the caller queried with a wildcard) NVD cannot filter for us, so we
    would otherwise pick up ancient CVEs pinned to versions from decades ago
    (CVE-1999-0067 tagged at ``apache:http_server:1.0.3`` on modern Apache).

    Logic:
    - No cpeMatch entries for this product → fall back to loose check.
    - Versionless service → require at least one unconstrained CPE entry
      for this product. Any CPE pinned to a specific version or bounded
      range drops the CVE because we cannot confirm applicability.
    - Versioned service → require at least one CPE entry whose range (or
      pinned specific version at major.minor) covers the service version.
    """
    configurations = cve_data.get("configurations", [])
    if not configurations:
        return True  # keep; description-based match handled by _cve_matches_product

    matches = list(_iter_matching_cpe_entries(cve_data, product_lower))
    if not matches:
        return True  # different product entry; not our business to drop

    versionless = not version or _extract_version(version) == "*"
    if versionless:
        # Keep the CVE if at least one CPE entry is either:
        #   (a) truly unconstrained (version=``*`` with no range), OR
        #   (b) an explicit version range (versionStart/End*).
        #
        # Entries pinned to a bare specific version (``apache:1.0.3``) with
        # no range are the phantom-CVE pattern we want to drop — they cannot
        # be verified against an unknown service version and almost always
        # represent 1990s CVEs that NVD still indexes under the product.
        # Modern vendor CVEs (ESXi, CrushFTP, Apache 2.4) carry proper
        # ranges; those we keep and let the gold filter enforce recency.
        def _applicable(m: dict) -> bool:
            if not _cpe_entry_has_version_constraint(m):
                return True  # unconstrained — always applicable
            return any(m.get(k) for k in (
                "versionStartIncluding", "versionStartExcluding",
                "versionEndIncluding", "versionEndExcluding",
            ))
        return any(_applicable(m) for m in matches)

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

    # CVSS score (prefer v3.1 > v3.0 > v2)
    cvss = None
    cvss_vector = None
    severity = None
    metrics = cve_data.get("metrics", {})

    for metric_key in ("cvssMetricV31", "cvssMetricV30"):
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

    # Check for known exploits in references
    has_exploit = False
    exploit_url = None
    for ref in cve_data.get("references", []):
        tags = ref.get("tags", [])
        if "Exploit" in tags:
            has_exploit = True
            exploit_url = ref.get("url")
            break
        ref_url = ref.get("url", "")
        if "exploit-db.com" in ref_url or ("github.com" in ref_url and "exploit" in ref_url.lower()):
            has_exploit = True
            exploit_url = ref_url
            break

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
        description=description[:500],
        has_exploit=has_exploit,
        exploit_url=exploit_url,
        cwe_ids=cwe_ids,
        published=published,
        in_cisa_kev=in_cisa_kev,
        cisa_kev_added=cisa_kev_added,
    )


# --- Public API ---

def enrich_service(
    product: str,
    version: str,
    cache: CVECache | None = None,
    cpe_list: list[str] | None = None,
) -> EnrichmentResult:
    """Find CVEs for a specific service.

    Uses CPE-based matching when available, falls back to keyword search.

    Args:
        product: Software product name (e.g. "OpenSSH", "Apache httpd")
        version: Version string (e.g. "7.4", "2.4.49")
        cache: Optional CVE cache instance.
        cpe_list: CPE URIs from nmap service detection.

    Returns:
        EnrichmentResult with found CVEs.
    """
    if not product:
        return EnrichmentResult(product="", version=version or "", error="Missing product")

    if cache is None:
        cache = CVECache()

    # Determine best query strategy
    cpe23 = _get_cpe_for_service(cpe_list or [], product, version)

    # Cache key: CPE-based if available, else product:version
    cache_key = cpe23 if cpe23 else f"kw:{product.lower().strip()}:{(version or '').lower().strip()}"

    # Check cache
    cached = cache.get(cache_key)
    if cached is not None:
        return EnrichmentResult(product=product, version=version or "", cves=cached, from_cache=True)

    # Query NVD. NvdTransientError bubbles up from _execute_nvd_query when
    # NVD is unreachable after retries — we refuse to cache that outcome
    # (empty list from a failed query would silently hide real CVEs for a
    # week). Every other outcome (including a legitimate empty result) is
    # authoritative and gets cached.
    cves: list[CVEInfo] = []
    try:
        if cpe23:
            cpe_result = _query_nvd_cpe(cpe23)
            if cpe_result is None:
                # CPE not recognized by NVD (404) — fall back to keyword search.
                # Applies the three-rule strategy: if we have a parseable version,
                # search "product version"; otherwise search by product alone and
                # let _query_nvd_keyword return top-critical recent entries.
                clean_ver = _extract_version(version)
                logger.info("CPE 404 for %s, falling back to keyword: %s %s", cpe23, product, clean_ver)
                cves = _query_nvd_keyword(product, clean_ver)
            elif not cpe_result and _has_specific_version(cpe23):
                # Specific-version query returned zero CVEs. Common NVD quirk: a
                # vendor pins CVEs to major version only (e.g.
                # vmware:vcenter_server:7.0) but nmap reports a patch level
                # (7.0.3), so literal match fails. Retry once with the version
                # wildcarded out — works across vendors (not a product-specific
                # hack), and preserves the "top-critical CVEs for this service"
                # principle because _query_nvd_cpe still filters by CVSS.
                relaxed = _relax_cpe_version(cpe23)
                if relaxed and relaxed != cpe23:
                    logger.info("CPE %s returned 0 CVEs, retrying with %s", cpe23, relaxed)
                    # Thread the original service version so the applicability
                    # filter can still do range/major.minor matching — without
                    # this the relaxed CPE falls into the unconstrained-only
                    # rule and drops every modern vendor CVE.
                    cves = _query_nvd_cpe(relaxed, service_version_override=version) or []
            else:
                cves = cpe_result
        elif version:
            clean_ver = _extract_version(version)
            if clean_ver != "*":
                cves = _query_nvd_keyword(product, clean_ver)
            else:
                return EnrichmentResult(product=product, version=version or "", error="No parseable version")
        else:
            # No CPE and no version — skip (too noisy)
            return EnrichmentResult(product=product, version="", error="No CPE and no version")
    except NvdTransientError as e:
        # NVD failed transiently — skip without caching. Next run will
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
        result = session.run(
            """
            MATCH (h:Host)-[:HAS_SERVICE]->(s:Service)
            WHERE (s.cpe IS NOT NULL OR s.product IS NOT NULL)
            AND NOT (s)-[:HAS_VULN]->(:Vulnerability {source: 'nvd'})
            RETURN DISTINCT
                s.product AS product,
                s.version AS version,
                s.cpe AS cpe
            """
        )

        services = [(r["product"], r["version"], r["cpe"]) for r in result]

    # Deduplicate by cache key to avoid querying same product twice
    seen_keys: set[str] = set()
    unique_services = []
    for product, version, cpe_str in services:
        cpe_list = cpe_str.split(";") if cpe_str else []
        cpe23 = _get_cpe_for_service(cpe_list, product, version)
        key = cpe23 if cpe23 else f"kw:{(product or '').lower()}:{(version or '').lower()}"
        if key not in seen_keys:
            seen_keys.add(key)
            unique_services.append((product, version, cpe_list))

    logger.info(
        "Found %d unique services to enrich (%d total before dedup)",
        len(unique_services),
        len(services),
    )

    total = len(unique_services)
    for idx, (product, version, cpe_list) in enumerate(unique_services, 1):
        stats["services_checked"] += 1
        if progress_callback:
            label = f"{product or '?'}{(' ' + version) if version else ''}"
            try:
                progress_callback(idx, total, f"NVD: {label}")
            except Exception:  # noqa: BLE001
                pass
        enrichment = enrich_service(product or "", version or "", cache, cpe_list)

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
            # Track query type
            cpe23 = _get_cpe_for_service(cpe_list, product, version)
            if cpe23:
                stats["cpe_queries"] += 1
            else:
                stats["keyword_queries"] += 1

        if enrichment.cves:
            stats["services_with_cves"] += 1
            stats["total_cves_found"] += len(enrichment.cves)

            # Write CVEs to Neo4j — link to ALL services matching this product+version or CPE
            with get_session() as session:
                for cve in enrichment.cves:
                    _upsert_vulnerability(session, product or "", version or "", cpe_list, cve)

    return stats


def _upsert_vulnerability(
    session,
    product: str,
    version: str,
    cpe_list: list[str],
    cve: CVEInfo,
) -> None:
    """Create/update Vulnerability node and link to matching services.

    Confidence lives on the HAS_VULN relationship, not on the node — a
    script-confirmed upgrade on one host must not leak "confirmed" onto
    every other host sharing the same CVE ID. Default for NVD-sourced
    findings is 'check'; script_upgrades or AI triage can lift a
    specific edge to 'likely' / 'confirmed' independently.
    """
    session.run(
        """
        MERGE (v:Vulnerability {cve_id: $cve_id})
        ON CREATE SET
            v.cvss = $cvss,
            v.cvss_vector = $cvss_vector,
            v.severity = $severity,
            v.description = $description,
            v.has_exploit = $has_exploit,
            v.exploit_url = $exploit_url,
            v.epss = $epss,
            v.in_cisa_kev = $in_cisa_kev,
            v.cisa_kev_added = $cisa_kev_added,
            v.source = 'nvd'
        ON MATCH SET
            v.cvss = COALESCE($cvss, v.cvss),
            v.severity = COALESCE($severity, v.severity),
            v.has_exploit = CASE WHEN $has_exploit THEN true ELSE v.has_exploit END,
            v.in_cisa_kev = CASE WHEN $in_cisa_kev THEN true ELSE v.in_cisa_kev END,
            v.cisa_kev_added = COALESCE($cisa_kev_added, v.cisa_kev_added)
        """,
        cve_id=cve.cve_id,
        cvss=cve.cvss,
        cvss_vector=cve.cvss_vector,
        severity=cve.severity,
        description=cve.description,
        has_exploit=cve.has_exploit,
        exploit_url=cve.exploit_url,
        epss=cve.epss,
        in_cisa_kev=cve.in_cisa_kev,
        cisa_kev_added=cve.cisa_kev_added,
    )

    # Link to matching services by product+version
    if product and version:
        session.run(
            """
            MATCH (s:Service)
            WHERE s.product = $product AND s.version = $version
            MATCH (v:Vulnerability {cve_id: $cve_id})
            MERGE (s)-[rel:HAS_VULN]->(v)
            ON CREATE SET rel.confidence = 'check'
            """,
            product=product,
            version=version,
            cve_id=cve.cve_id,
        )

    # Also link by CPE (catches services where product name differs but CPE matches)
    # Must include version to avoid cross-version pollution
    for cpe in cpe_list:
        cpe23 = _cpe22_to_23(cpe)
        if cpe23:
            parts = cpe23.split(":")
            if len(parts) >= 6:
                cpe_vendor = parts[3]
                cpe_product = parts[4]
                cpe_version = parts[5]
                # Build prefix with version if available
                if cpe_version and cpe_version != "*":
                    cpe_prefix = f"cpe:/a:{cpe_vendor}:{cpe_product}:{cpe_version}"
                else:
                    cpe_prefix = f"cpe:/a:{cpe_vendor}:{cpe_product}"
                session.run(
                    """
                    MATCH (s:Service)
                    WHERE s.cpe STARTS WITH $prefix OR s.cpe CONTAINS $contains
                    MATCH (v:Vulnerability {cve_id: $cve_id})
                    MERGE (s)-[rel:HAS_VULN]->(v)
                    ON CREATE SET rel.confidence = 'check'
                    """,
                    prefix=cpe_prefix,
                    contains=f";{cpe_prefix}",
                    cve_id=cve.cve_id,
                )
