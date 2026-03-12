"""Tests for CVE enricher.

Uses mocked NVD API responses to avoid real API calls during testing.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from cauldron.ai.cve_enricher import (
    CVECache,
    CVEInfo,
    _build_cache_key,
    _parse_cve,
    enrich_service,
)


# Sample NVD API response for testing
SAMPLE_CVE_RESPONSE = {
    "totalResults": 2,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "descriptions": [
                    {"lang": "en", "value": "Path traversal in Apache HTTP Server 2.4.49 allows reading files outside the document root."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 7.5,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                "baseSeverity": "HIGH",
                            }
                        }
                    ]
                },
                "references": [
                    {"url": "https://exploit-db.com/exploits/50383", "tags": ["Exploit"]},
                    {"url": "https://httpd.apache.org/security/vulnerabilities_24.html", "tags": ["Vendor Advisory"]},
                ],
            }
        },
        {
            "cve": {
                "id": "CVE-2021-42013",
                "descriptions": [
                    {"lang": "en", "value": "Insufficient fix for CVE-2021-41773 in Apache HTTP Server 2.4.50."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
                "references": [],
            }
        },
    ],
}


class TestCVEInfo:
    def test_to_dict_and_back(self):
        cve = CVEInfo(
            cve_id="CVE-2021-41773",
            cvss=7.5,
            severity="HIGH",
            description="Path traversal",
            has_exploit=True,
        )
        d = cve.to_dict()
        cve2 = CVEInfo.from_dict(d)
        assert cve2.cve_id == "CVE-2021-41773"
        assert cve2.cvss == 7.5
        assert cve2.has_exploit is True

    def test_from_dict_ignores_unknown_keys(self):
        data = {"cve_id": "CVE-2024-0001", "unknown_field": "ignored"}
        cve = CVEInfo.from_dict(data)
        assert cve.cve_id == "CVE-2024-0001"


class TestCVECache:
    def test_cache_miss(self, tmp_path: Path):
        cache = CVECache(tmp_path / "cache.json")
        assert cache.get("openssh:7.4") is None

    def test_cache_put_and_get(self, tmp_path: Path):
        cache = CVECache(tmp_path / "cache.json")
        cves = [CVEInfo(cve_id="CVE-2021-41773", cvss=7.5)]
        cache.put("apache httpd:2.4.49", cves)

        result = cache.get("apache httpd:2.4.49")
        assert result is not None
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2021-41773"

    def test_cache_persists_to_file(self, tmp_path: Path):
        cache_file = tmp_path / "cache.json"
        cache1 = CVECache(cache_file)
        cache1.put("test:1.0", [CVEInfo(cve_id="CVE-2024-0001")])

        # Load from file
        cache2 = CVECache(cache_file)
        result = cache2.get("test:1.0")
        assert result is not None
        assert result[0].cve_id == "CVE-2024-0001"

    def test_cache_empty_results(self, tmp_path: Path):
        cache = CVECache(tmp_path / "cache.json")
        cache.put("safe-product:1.0", [])

        result = cache.get("safe-product:1.0")
        assert result is not None
        assert result == []

    def test_cache_size(self, tmp_path: Path):
        cache = CVECache(tmp_path / "cache.json")
        assert cache.size == 0
        cache.put("a:1", [])
        cache.put("b:2", [])
        assert cache.size == 2


class TestParseCVE:
    def test_parse_full_cve(self):
        cve_data = SAMPLE_CVE_RESPONSE["vulnerabilities"][0]["cve"]
        cve = _parse_cve(cve_data)

        assert cve is not None
        assert cve.cve_id == "CVE-2021-41773"
        assert cve.cvss == 7.5
        assert cve.severity == "HIGH"
        assert "Path traversal" in cve.description
        assert cve.has_exploit is True
        assert "exploit-db.com" in cve.exploit_url

    def test_parse_cve_without_exploit(self):
        cve_data = SAMPLE_CVE_RESPONSE["vulnerabilities"][1]["cve"]
        cve = _parse_cve(cve_data)

        assert cve is not None
        assert cve.cve_id == "CVE-2021-42013"
        assert cve.cvss == 9.8
        assert cve.severity == "CRITICAL"
        assert cve.has_exploit is False

    def test_parse_cve_v2_fallback(self):
        cve_data = {
            "id": "CVE-2016-10009",
            "descriptions": [{"lang": "en", "value": "Old vuln"}],
            "metrics": {
                "cvssMetricV2": [
                    {
                        "cvssData": {"baseScore": 7.5, "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
                        "baseSeverity": "HIGH",
                    }
                ]
            },
            "references": [],
        }
        cve = _parse_cve(cve_data)
        assert cve is not None
        assert cve.cvss == 7.5

    def test_parse_cve_no_id_returns_none(self):
        assert _parse_cve({}) is None


class TestBuildCacheKey:
    def test_normalizes_case(self):
        assert _build_cache_key("OpenSSH", "7.4") == "openssh:7.4"

    def test_strips_whitespace(self):
        assert _build_cache_key(" Apache httpd ", " 2.4.49 ") == "apache httpd:2.4.49"


class TestEnrichService:
    def test_missing_product(self, tmp_path: Path):
        cache = CVECache(tmp_path / "cache.json")
        result = enrich_service("", "1.0", cache)
        assert result.error is not None

    def test_missing_version(self, tmp_path: Path):
        cache = CVECache(tmp_path / "cache.json")
        result = enrich_service("OpenSSH", "", cache)
        assert result.error is not None

    def test_returns_cached_results(self, tmp_path: Path):
        cache = CVECache(tmp_path / "cache.json")
        cache.put("openssh:7.4", [CVEInfo(cve_id="CVE-2016-10009", cvss=7.3)])

        result = enrich_service("OpenSSH", "7.4", cache)
        assert result.from_cache is True
        assert len(result.cves) == 1
        assert result.cves[0].cve_id == "CVE-2016-10009"

    @patch("cauldron.ai.cve_enricher._query_nvd")
    def test_queries_api_on_cache_miss(self, mock_query, tmp_path: Path):
        cache = CVECache(tmp_path / "cache.json")
        mock_query.return_value = [CVEInfo(cve_id="CVE-2021-41773", cvss=7.5)]

        result = enrich_service("Apache httpd", "2.4.49", cache)
        assert result.from_cache is False
        assert len(result.cves) == 1
        mock_query.assert_called_once_with("Apache httpd", "2.4.49")

    @patch("cauldron.ai.cve_enricher._query_nvd")
    def test_caches_api_results(self, mock_query, tmp_path: Path):
        cache = CVECache(tmp_path / "cache.json")
        mock_query.return_value = [CVEInfo(cve_id="CVE-2021-41773", cvss=7.5)]

        # First call hits API
        enrich_service("Apache httpd", "2.4.49", cache)
        assert mock_query.call_count == 1

        # Second call uses cache
        result2 = enrich_service("Apache httpd", "2.4.49", cache)
        assert result2.from_cache is True
        assert mock_query.call_count == 1  # no additional API call

    @patch("cauldron.ai.cve_enricher._query_nvd")
    def test_caches_empty_results(self, mock_query, tmp_path: Path):
        cache = CVECache(tmp_path / "cache.json")
        mock_query.return_value = []

        enrich_service("SafeProduct", "1.0", cache)
        result2 = enrich_service("SafeProduct", "1.0", cache)

        assert result2.from_cache is True
        assert result2.cves == []
        assert mock_query.call_count == 1
