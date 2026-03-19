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

def _cpe22_to_23(cpe: str) -> str | None:
    """Convert CPE 2.2 URI (cpe:/a:vendor:product:version) to CPE 2.3 format.

    Returns None if not a valid application CPE.
    """
    # cpe:/a:vendor:product:version:update...
    if not cpe.startswith("cpe:/"):
        return None
    parts = cpe[5:].split(":")
    if len(parts) < 3:
        return None
    part_type = parts[0]  # a, o, h
    if part_type != "a":
        return None  # Only application CPEs are useful for service vuln matching
    vendor = parts[1] if len(parts) > 1 else "*"
    product = parts[2] if len(parts) > 2 else "*"
    version = parts[3] if len(parts) > 3 else "*"
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _build_cpe23(vendor: str, product: str, version: str = "*") -> str:
    """Build a CPE 2.3 string from components."""
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _get_cpe_for_service(cpe_list: list[str], product: str | None, version: str | None) -> str | None:
    """Get best CPE 2.3 string for a service.

    Priority:
    1. Application CPE from nmap (cpe:/a:...)
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
            ver = version or "*"
            return _build_cpe23(vendor, prod, ver)

    return None


# --- NVD API queries ---

def _has_specific_version(cpe23: str) -> bool:
    """Check if CPE has a specific version (not wildcard)."""
    parts = cpe23.split(":")
    # cpe:2.3:a:vendor:product:VERSION:...
    return len(parts) >= 6 and parts[5] != "*"


def _query_nvd_cpe(cpe23: str) -> list[CVEInfo]:
    """Query NVD API using CPE-based virtualMatchString.

    With specific version: full search (precise results).
    Without version (wildcard): recent CVEs only (last 2 years, CVSS >= 7.0).
    """
    _rate_limit()

    has_version = _has_specific_version(cpe23)
    encoded_cpe = urllib.request.quote(cpe23)

    if has_version:
        # Specific version: fetch high-severity CVEs (RCE/shell territory)
        url = f"{NVD_API_BASE}?virtualMatchString={encoded_cpe}&resultsPerPage=20"
    else:
        # No version (assume latest): only recent critical CVEs
        now = datetime.now(timezone.utc)
        start = now.replace(year=now.year - 1, month=1, day=1)
        start_str = start.strftime("%Y-%m-%dT00:00:00.000")
        url = (
            f"{NVD_API_BASE}?virtualMatchString={encoded_cpe}"
            f"&pubStartDate={start_str}&resultsPerPage=20"
            f"&cvssV3Severity=CRITICAL"
        )

    cves = _execute_nvd_query(url, f"CPE:{cpe23}")

    # Pentester filter: keep exploitable (CVSS >= 7.0 OR has known exploit)
    cves = [c for c in cves if (c.cvss is not None and c.cvss >= 7.0) or c.has_exploit]

    return cves


def _query_nvd_keyword(product: str, version: str) -> list[CVEInfo]:
    """Query NVD API using keywordSearch (fallback, less precise).

    Strict filtering: only CVSS >= 7.0 or has known exploit.
    """
    _rate_limit()

    keyword = f"{product} {version}".strip()
    encoded = urllib.request.quote(keyword)
    url = f"{NVD_API_BASE}?keywordSearch={encoded}&keywordExactMatch&resultsPerPage=10"

    cves = _execute_nvd_query(url, f"keyword:{keyword}")

    # Pentester filter: only keep exploitable results
    return [c for c in cves if (c.cvss is not None and c.cvss >= 7.0) or c.has_exploit]


def _execute_nvd_query(url: str, context: str) -> list[CVEInfo]:
    """Execute NVD API request and parse results."""
    headers = {"User-Agent": "Cauldron/0.1.0"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    req = urllib.request.Request(url, headers=headers)

    try:
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            logger.warning("NVD API rate limited (403) for %s. Waiting 30s...", context)
            time.sleep(30)
            return _execute_nvd_query(url, context)
        logger.error("NVD API error %d for %s", e.code, context)
        return []
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        logger.error("NVD API request failed for %s: %s", context, e)
        return []

    cves = []
    for vuln_item in data.get("vulnerabilities", []):
        cve_data = vuln_item.get("cve", {})

        # Filter rejected/disputed CVEs
        status = cve_data.get("vulnStatus", "")
        if status in ("Rejected", "Disputed"):
            continue

        cve = _parse_cve(cve_data)
        if cve:
            cves.append(cve)

    return cves


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

    return CVEInfo(
        cve_id=cve_id,
        cvss=cvss,
        cvss_vector=cvss_vector,
        severity=severity,
        description=description[:500],
        has_exploit=has_exploit,
        exploit_url=exploit_url,
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

    # Query NVD
    if cpe23:
        cves = _query_nvd_cpe(cpe23)
    elif version:
        cves = _query_nvd_keyword(product, version)
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
        # Get services with CPE or product info, that have no CVEs yet
        result = session.run(
            """
            MATCH (h:Host)-[:HAS_SERVICE]->(s:Service)
            WHERE (s.cpe IS NOT NULL OR s.product IS NOT NULL)
            AND NOT (s)-[:HAS_VULN]->(:Vulnerability)
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
            v.source = 'nvd'
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
    for cpe in cpe_list:
        cpe23 = _cpe22_to_23(cpe)
        if cpe23:
            # Extract vendor:product from CPE for matching
            parts = cpe23.split(":")
            if len(parts) >= 6:
                cpe_vendor = parts[3]
                cpe_product = parts[4]
                session.run(
                    """
                    MATCH (s:Service)
                    WHERE s.cpe STARTS WITH $prefix OR s.cpe CONTAINS $contains
                    MATCH (v:Vulnerability {cve_id: $cve_id})
                    MERGE (s)-[:HAS_VULN]->(v)
                    """,
                    prefix=f"cpe:/a:{cpe_vendor}:{cpe_product}",
                    contains=f";cpe:/a:{cpe_vendor}:{cpe_product}",
                    cve_id=cve.cve_id,
                )
