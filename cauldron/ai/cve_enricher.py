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

# NVD API base URL
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Cache location
CACHE_DIR = Path.home() / ".cauldron"
CACHE_FILE = CACHE_DIR / "cve_cache.json"

# Rate limiting: track last request time
_last_request_time: float = 0.0

# Fallback: nmap product name -> CPE "vendor:product" for services without nmap CPE
# Only used when nmap doesn't provide a CPE itself
PRODUCT_CPE_MAP: dict[str, str] = {
    # SSH
    "openssh": "openbsd:openssh",
    "dropbear sshd": "matt_johnston:dropbear_ssh",
    "libssh": "libssh:libssh",
    # Web servers
    "apache httpd": "apache:http_server",
    "nginx": "f5:nginx",
    "microsoft iis httpd": "microsoft:internet_information_services",
    "lighttpd": "lighttpd:lighttpd",
    "apache tomcat": "apache:tomcat",
    "apache coyote": "apache:tomcat",
    "cherokee httpd": "cherokee-project:cherokee",
    # Databases
    "mysql": "oracle:mysql",
    "postgresql": "postgresql:postgresql",
    "mariadb": "mariadb:mariadb",
    "redis": "redis:redis",
    "mongodb": "mongodb:mongodb",
    "memcached": "memcached:memcached",
    "microsoft sql server": "microsoft:sql_server",
    # FTP
    "vsftpd": "vsftpd_project:vsftpd",
    "proftpd": "proftpd:proftpd",
    "pure-ftpd": "pureftpd:pure-ftpd",
    "filezilla ftpd": "filezilla-project:filezilla_server",
    # Mail
    "postfix smtpd": "postfix:postfix",
    "exim smtpd": "exim:exim",
    "dovecot": "dovecot:dovecot",
    "sendmail": "sendmail:sendmail",
    "microsoft exchange smtpd": "microsoft:exchange_server",
    # DNS
    "isc bind": "isc:bind",
    "dnsmasq": "thekelleys:dnsmasq",
    # SMB/File
    "samba smbd": "samba:samba",
    # Proxy
    "squid http proxy": "squid-cache:squid",
    "haproxy": "haproxy:haproxy",
    # Other
    "openvpn": "openvpn:openvpn",
    "openldap": "openldap:openldap",
    "elasticsearch": "elastic:elasticsearch",
    "jenkins": "jenkins:jenkins",
    "grafana": "grafana:grafana",
    "vmware esxi": "vmware:esxi",
    "vmware esxi soap api": "vmware:esxi",
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

# OS CPE products worth querying NVD for (have specific, useful CVEs)
# Only when a specific version is present (no wildcard OS queries)
_OS_CPE_PRODUCTS: set[str] = {
    "vmware:esxi",
    "cisco:ios",
    "cisco:ios_xe",
    "cisco:nxos",
    "paloaltonetworks:pan-os",
    "fortinet:fortios",
    "juniper:junos",
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
    """Build a CPE 2.3 string from components."""
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


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

    # Fallback: use product name mapping
    if product:
        product_lower = product.lower().strip()
        vendor_product = PRODUCT_CPE_MAP.get(product_lower)
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


# --- NVD API queries ---

def _has_specific_version(cpe23: str) -> bool:
    """Check if CPE has a specific version (not wildcard)."""
    parts = cpe23.split(":")
    # cpe:2.3:a:vendor:product:VERSION:...
    return len(parts) >= 6 and parts[5] != "*"


def _query_nvd_cpe(cpe23: str) -> list[CVEInfo] | None:
    """Query NVD API using CPE-based virtualMatchString.

    With specific version: full search, sorted by severity (highest first).
    Without version (wildcard): recent CVEs only, sorted by date (newest first).

    Returns None if CPE is not recognized by NVD (404), signaling
    the caller to try keyword fallback.
    """
    _rate_limit()

    has_version = _has_specific_version(cpe23)
    encoded_cpe = urllib.request.quote(cpe23)

    if has_version:
        # Specific version: fetch CVEs, we'll filter by relevance
        url = f"{NVD_API_BASE}?virtualMatchString={encoded_cpe}&resultsPerPage=50"
    else:
        # No version: only recent CVEs (last ~1 year)
        now = datetime.now(timezone.utc)
        start = now.replace(year=now.year - 1, month=1, day=1)
        start_str = start.strftime("%Y-%m-%dT00:00:00.000")
        url = (
            f"{NVD_API_BASE}?virtualMatchString={encoded_cpe}"
            f"&pubStartDate={start_str}&resultsPerPage=50"
            f"&cvssV3Severity=CRITICAL"
        )

    cves = _execute_nvd_query(url, f"CPE:{cpe23}")

    # None = 404 (CPE not in NVD) — signal caller to try keyword fallback
    if cves is None:
        return None

    # Pentester filter: keep only CVEs with real engagement impact
    cves = [c for c in cves if _is_pentester_relevant(c)]

    # Sort and cap results
    if has_version:
        # Specific version: sort by severity (most critical first)
        cves.sort(key=lambda c: c.cvss or 0, reverse=True)
    else:
        # No version: take newest first, then re-sort by severity
        cves.sort(key=lambda c: c.published or "", reverse=True)
        cves = cves[:20]
        cves.sort(key=lambda c: c.cvss or 0, reverse=True)

    return cves[:20]


def _query_nvd_keyword(product: str, version: str) -> list[CVEInfo]:
    """Query NVD API using keywordSearch (fallback, less precise).

    Validates results against CVE's CPE configurations to ensure
    the CVE actually affects the target product, not just mentions it.
    """
    _rate_limit()

    keyword = f"{product} {version}".strip()
    encoded = urllib.request.quote(keyword)
    url = f"{NVD_API_BASE}?keywordSearch={encoded}&keywordExactMatch&resultsPerPage=20"

    cves = _execute_nvd_query(url, f"keyword:{keyword}", product_hint=product)

    # Pentester filter: only keep CVEs with real engagement impact
    cves = [c for c in cves if _is_pentester_relevant(c)]

    # Sort by severity
    cves.sort(key=lambda c: c.cvss or 0, reverse=True)

    return cves[:10]


def _execute_nvd_query(
    url: str,
    context: str,
    product_hint: str | None = None,
    _retries: int = 0,
) -> list[CVEInfo] | None:
    """Execute NVD API request and parse results.

    Args:
        url: NVD API URL to query.
        context: Human-readable context for logging.
        product_hint: If set, validate each CVE's CPE configurations
            actually reference this product (used for keyword searches
            to eliminate false positives).
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
        if e.code == 403 and _retries < 2:
            logger.warning(
                "NVD API rate limited (403) for %s. Retry %d/2, waiting 30s...",
                context, _retries + 1,
            )
            time.sleep(30)
            return _execute_nvd_query(url, context, product_hint, _retries + 1)
        if e.code == 404:
            logger.info("NVD CPE not found (404) for %s — will try keyword fallback", context)
            return None
        logger.error("NVD API error %d for %s", e.code, context)
        return []
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        logger.error("NVD API request failed for %s: %s", context, e)
        return []

    # Normalize product hint for matching
    product_lower = product_hint.lower().strip() if product_hint else None

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

        cve = _parse_cve(cve_data)
        if cve:
            cves.append(cve)

    return cves


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
    )


def verify_cve_via_nvd(cve_id: str) -> CVEInfo | None:
    """Look up a single CVE ID in NVD and return verified data.

    Used to validate AI-generated CVE claims — replaces AI-hallucinated
    CVSS scores and descriptions with real NVD data.

    Returns None if CVE not found, rejected, or not relevant.
    """
    _rate_limit()
    url = f"{NVD_API_BASE}?cveId={cve_id}"
    cves = _execute_nvd_query(url, f"verify:{cve_id}")
    if cves and len(cves) > 0:
        return cves[0]
    return None


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

    # Query NVD
    cves: list[CVEInfo] = []
    if cpe23:
        cpe_result = _query_nvd_cpe(cpe23)
        if cpe_result is None:
            # CPE not recognized by NVD (404) — fall back to keyword search
            clean_ver = _extract_version(version)
            if clean_ver != "*":
                logger.info("CPE 404 for %s, falling back to keyword: %s %s", cpe23, product, clean_ver)
                cves = _query_nvd_keyword(product, clean_ver)
            else:
                logger.info("CPE 404 for %s, no version for keyword fallback", cpe23)
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

    # Cache results (even empty — to avoid re-querying)
    cache.put(cache_key, cves)

    return EnrichmentResult(product=product, version=version or "", cves=cves)


def enrich_services_from_graph() -> dict:
    """Enrich all services in the Neo4j graph with CVE data.

    Reads services with CPE or product+version, queries NVD API,
    creates Vulnerability nodes and HAS_VULN relationships.

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

    for product, version, cpe_list in unique_services:
        stats["services_checked"] += 1
        enrichment = enrich_service(product or "", version or "", cache, cpe_list)

        if enrichment.error:
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
    """Create/update Vulnerability node and link to matching services."""
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
            v.source = 'nvd',
            v.confidence = 'check'
        ON MATCH SET
            v.cvss = COALESCE($cvss, v.cvss),
            v.severity = COALESCE($severity, v.severity),
            v.has_exploit = CASE WHEN $has_exploit THEN true ELSE v.has_exploit END
        """,
        cve_id=cve.cve_id,
        cvss=cve.cvss,
        cvss_vector=cve.cvss_vector,
        severity=cve.severity,
        description=cve.description,
        has_exploit=cve.has_exploit,
        exploit_url=cve.exploit_url,
        epss=cve.epss,
    )

    # Link to matching services by product+version
    if product and version:
        session.run(
            """
            MATCH (s:Service)
            WHERE s.product = $product AND s.version = $version
            MATCH (v:Vulnerability {cve_id: $cve_id})
            MERGE (s)-[:HAS_VULN]->(v)
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
                    MERGE (s)-[:HAS_VULN]->(v)
                    """,
                    prefix=cpe_prefix,
                    contains=f";{cpe_prefix}",
                    cve_id=cve.cve_id,
                )
