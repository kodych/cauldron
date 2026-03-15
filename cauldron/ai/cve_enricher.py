"""CVE enrichment via NVD API.

Queries the National Vulnerability Database for known CVEs matching
service product+version pairs found during scanning.

Features:
- Local JSON file cache to avoid repeated API calls
- Rate limiting (NVD: 5 req/30s without key, 50 req/30s with key)
- CVSS v3.1/v3.0/v2 score extraction
- EPSS probability (if available)
"""

from __future__ import annotations

import json
import logging
import time
import urllib.request
import urllib.error
from dataclasses import asdict, dataclass, field
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
                # Migrate old format (list) to new format (dict with _cached_at)
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
        """Get cached CVEs for a product+version key. Returns None if expired."""
        entry = self._data.get(key)
        if entry is None:
            return None
        cached_at = entry.get("_cached_at", 0)
        if self._ttl > 0 and time.time() - cached_at > self._ttl:
            del self._data[key]
            return None
        return [CVEInfo.from_dict(d) for d in entry.get("cves", [])]

    def put(self, key: str, cves: list[CVEInfo]) -> None:
        """Cache CVEs for a product+version key with timestamp."""
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
    # Without API key: 5 requests per 30 seconds = 6s between requests
    # With API key: 50 requests per 30 seconds = 0.6s between requests
    delay = 0.7 if settings.nvd_api_key else 6.5
    elapsed = time.time() - _last_request_time
    if elapsed < delay:
        time.sleep(delay - elapsed)
    _last_request_time = time.time()


def _build_cache_key(product: str, version: str) -> str:
    """Build a normalized cache key from product+version."""
    return f"{product.lower().strip()}:{version.lower().strip()}"


def _query_nvd(product: str, version: str) -> list[CVEInfo]:
    """Query NVD API for CVEs matching product+version."""
    _rate_limit()

    # Build search query
    keyword = f"{product} {version}".strip()
    params = urllib.request.quote(keyword)
    url = f"{NVD_API_BASE}?keywordSearch={params}&resultsPerPage=20"

    headers = {"User-Agent": "Cauldron/0.1.0"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    req = urllib.request.Request(url, headers=headers)

    try:
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            logger.warning("NVD API rate limited (403). Waiting and retrying...")
            time.sleep(30)
            return _query_nvd(product, version)
        logger.error("NVD API error %d for '%s'", e.code, keyword)
        return []
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        logger.error("NVD API request failed for '%s': %s", keyword, e)
        return []

    cves = []
    for vuln_item in data.get("vulnerabilities", []):
        cve_data = vuln_item.get("cve", {})
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
        if "exploit-db.com" in ref_url or "github.com" in ref_url and "exploit" in ref_url.lower():
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


def enrich_service(product: str, version: str, cache: CVECache | None = None) -> EnrichmentResult:
    """Find CVEs for a specific product+version.

    Args:
        product: Software product name (e.g. "OpenSSH", "Apache httpd")
        version: Version string (e.g. "7.4", "2.4.49")
        cache: Optional CVE cache instance. Created if not provided.

    Returns:
        EnrichmentResult with found CVEs.
    """
    if not product or not version:
        return EnrichmentResult(product=product or "", version=version or "", error="Missing product or version")

    if cache is None:
        cache = CVECache()

    key = _build_cache_key(product, version)

    # Check cache first
    cached = cache.get(key)
    if cached is not None:
        return EnrichmentResult(product=product, version=version, cves=cached, from_cache=True)

    # Query NVD
    cves = _query_nvd(product, version)

    # Cache results (even empty — to avoid re-querying)
    cache.put(key, cves)

    return EnrichmentResult(product=product, version=version, cves=cves)


def enrich_services_from_graph() -> dict:
    """Enrich all services in the Neo4j graph with CVE data.

    Reads services with product+version, queries NVD API,
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
    }

    cache = CVECache()

    with get_session() as session:
        # Get services with product+version that have no CVEs yet
        result = session.run(
            """
            MATCH (h:Host)-[:HAS_SERVICE]->(s:Service)
            WHERE s.product IS NOT NULL AND s.version IS NOT NULL
            AND NOT (s)-[:HAS_VULN]->(:Vulnerability)
            RETURN DISTINCT s.product AS product, s.version AS version
            """
        )

        pairs = [(r["product"], r["version"]) for r in result]

    logger.info("Found %d unique product+version pairs to enrich", len(pairs))

    for product, version in pairs:
        stats["services_checked"] += 1
        enrichment = enrich_service(product, version, cache)

        if enrichment.error:
            stats["errors"] += 1
            continue

        if enrichment.from_cache:
            stats["from_cache"] += 1
        else:
            stats["api_calls"] += 1

        if enrichment.cves:
            stats["services_with_cves"] += 1
            stats["total_cves_found"] += len(enrichment.cves)

            # Write CVEs to Neo4j
            with get_session() as session:
                for cve in enrichment.cves:
                    _upsert_vulnerability(session, product, version, cve)

    return stats


def _upsert_vulnerability(session, product: str, version: str, cve: CVEInfo) -> None:
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
            v.epss = $epss
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

    # Link to matching services
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
