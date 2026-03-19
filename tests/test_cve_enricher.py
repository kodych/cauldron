"""Tests for CVE enricher.

Uses mocked NVD API responses to avoid real API calls during testing.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from cauldron.ai.cve_enricher import (
    CVECache,
    CVEInfo,
    PRODUCT_CPE_MAP,
    _cpe22_to_23,
    _get_cpe_for_service,
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
                "vulnStatus": "Analyzed",
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
                "vulnStatus": "Analyzed",
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

    def test_rejected_cve_filtered_in_execute(self):
        """Rejected CVEs are filtered in _execute_nvd_query, not _parse_cve."""
        cve_data = {"id": "CVE-2024-REJECTED", "vulnStatus": "Rejected", "descriptions": [], "metrics": {}, "references": []}
        # _parse_cve itself doesn't filter — it just parses
        cve = _parse_cve(cve_data)
        assert cve is not None  # parsing succeeds
        assert cve.cve_id == "CVE-2024-REJECTED"


class TestCPEConversion:
    def test_cpe22_app_to_23(self):
        result = _cpe22_to_23("cpe:/a:apache:http_server:2.4.49")
        assert result == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"

    def test_cpe22_no_version(self):
        result = _cpe22_to_23("cpe:/a:openbsd:openssh")
        assert result == "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"

    def test_cpe22_os_returns_none(self):
        """OS CPEs (cpe:/o:...) are not useful for service vuln matching."""
        result = _cpe22_to_23("cpe:/o:microsoft:windows")
        assert result is None

    def test_cpe22_hardware_returns_none(self):
        result = _cpe22_to_23("cpe:/h:hp:laserjet")
        assert result is None

    def test_invalid_cpe_returns_none(self):
        assert _cpe22_to_23("not-a-cpe") is None
        assert _cpe22_to_23("cpe:/a:x") is None  # too few parts


class TestGetCPEForService:
    def test_nmap_cpe_preferred(self):
        """Nmap's own CPE should be used over fallback mapping."""
        cpe_list = ["cpe:/a:apache:http_server:2.4.49"]
        result = _get_cpe_for_service(cpe_list, "Apache httpd", "2.4.49")
        assert result == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"

    def test_os_cpe_skipped_fallback_used(self):
        """If nmap only provides OS CPE, fallback mapping should be used."""
        cpe_list = ["cpe:/o:microsoft:windows"]
        result = _get_cpe_for_service(cpe_list, "Microsoft SQL Server", "2019")
        assert result is not None
        assert "microsoft:sql_server" in result

    def test_fallback_mapping(self):
        """Products in PRODUCT_CPE_MAP should get a CPE even without nmap CPE."""
        result = _get_cpe_for_service([], "OpenSSH", "7.4")
        assert result == "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"

    def test_unknown_product_no_cpe(self):
        """Unknown products without CPE should return None."""
        result = _get_cpe_for_service([], "CustomApp", "1.0")
        assert result is None

    def test_no_version_with_mapping(self):
        """Products with mapping but no version should use wildcard."""
        result = _get_cpe_for_service([], "nginx", None)
        assert result == "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"


class TestProductCPEMap:
    def test_map_has_common_products(self):
        """Verify key products are in the fallback mapping."""
        assert "openssh" in PRODUCT_CPE_MAP
        assert "apache httpd" in PRODUCT_CPE_MAP
        assert "nginx" in PRODUCT_CPE_MAP
        assert "mysql" in PRODUCT_CPE_MAP
        assert "vsftpd" in PRODUCT_CPE_MAP

    def test_map_values_format(self):
        """All values should be vendor:product format."""
        for product, cpe_vp in PRODUCT_CPE_MAP.items():
            parts = cpe_vp.split(":")
            assert len(parts) == 2, f"Bad CPE format for '{product}': '{cpe_vp}'"


class TestEnrichService:
    def test_missing_product(self, tmp_path: Path):
        cache = CVECache(tmp_path / "cache.json")
        result = enrich_service("", "1.0", cache)
        assert result.error is not None

    def test_no_cpe_no_version_skipped(self, tmp_path: Path):
        """Without CPE and without version, enrichment is too noisy."""
        cache = CVECache(tmp_path / "cache.json")
        result = enrich_service("SomeProduct", "", cache, cpe_list=[])
        assert result.error is not None

    def test_cpe_used_for_cache_key(self, tmp_path: Path):
        """When CPE is available, it should be the cache key."""
        cache = CVECache(tmp_path / "cache.json")
        cpe_key = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        cache.put(cpe_key, [CVEInfo(cve_id="CVE-2021-41773", cvss=7.5)])

        result = enrich_service("Apache httpd", "2.4.49", cache, cpe_list=["cpe:/a:apache:http_server:2.4.49"])
        assert result.from_cache is True
        assert len(result.cves) == 1

    @patch("cauldron.ai.cve_enricher._query_nvd_cpe")
    def test_cpe_query_when_available(self, mock_cpe_query, tmp_path: Path):
        cache = CVECache(tmp_path / "cache.json")
        mock_cpe_query.return_value = [CVEInfo(cve_id="CVE-2021-41773", cvss=7.5)]

        result = enrich_service("Apache httpd", "2.4.49", cache, cpe_list=["cpe:/a:apache:http_server:2.4.49"])
        assert result.from_cache is False
        assert len(result.cves) == 1
        mock_cpe_query.assert_called_once()

    @patch("cauldron.ai.cve_enricher._query_nvd_keyword")
    def test_keyword_fallback_when_no_cpe(self, mock_kw_query, tmp_path: Path):
        cache = CVECache(tmp_path / "cache.json")
        mock_kw_query.return_value = [CVEInfo(cve_id="CVE-2024-0001", cvss=5.0)]

        result = enrich_service("UnknownProduct", "3.1", cache, cpe_list=[])
        assert len(result.cves) == 1
        mock_kw_query.assert_called_once_with("UnknownProduct", "3.1")

    @patch("cauldron.ai.cve_enricher._query_nvd_cpe")
    def test_caches_api_results(self, mock_query, tmp_path: Path):
        cache = CVECache(tmp_path / "cache.json")
        mock_query.return_value = [CVEInfo(cve_id="CVE-2021-41773", cvss=7.5)]

        # First call hits API
        enrich_service("Apache httpd", "2.4.49", cache, cpe_list=["cpe:/a:apache:http_server:2.4.49"])
        assert mock_query.call_count == 1

        # Second call uses cache
        result2 = enrich_service("Apache httpd", "2.4.49", cache, cpe_list=["cpe:/a:apache:http_server:2.4.49"])
        assert result2.from_cache is True
        assert mock_query.call_count == 1

    @patch("cauldron.ai.cve_enricher._query_nvd_keyword")
    def test_caches_empty_results(self, mock_query, tmp_path: Path):
        cache = CVECache(tmp_path / "cache.json")
        mock_query.return_value = []

        enrich_service("SafeProduct", "1.0", cache, cpe_list=[])
        result2 = enrich_service("SafeProduct", "1.0", cache, cpe_list=[])

        assert result2.from_cache is True
        assert result2.cves == []
        assert mock_query.call_count == 1

    @patch("cauldron.ai.cve_enricher._query_nvd_cpe")
    def test_fallback_cpe_mapping_used(self, mock_cpe_query, tmp_path: Path):
        """Product in PRODUCT_CPE_MAP should use CPE query even without nmap CPE."""
        cache = CVECache(tmp_path / "cache.json")
        mock_cpe_query.return_value = []

        enrich_service("OpenSSH", "7.4", cache, cpe_list=[])
        mock_cpe_query.assert_called_once()
        call_args = mock_cpe_query.call_args[0][0]
        assert "openbsd:openssh:7.4" in call_args
