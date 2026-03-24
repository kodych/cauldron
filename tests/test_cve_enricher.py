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
    _cve_matches_product,
    _extract_version,
    _get_cpe_for_service,
    _is_pentester_relevant,
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
                "published": "2021-10-05T09:15:00.000",
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
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-22"}]}
                ],
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
                "published": "2021-10-07T16:15:00.000",
                "descriptions": [
                    {"lang": "en", "value": "Insufficient fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 allows remote code execution."}
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
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-78"}]}
                ],
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

    def test_cpe22_os_generic_returns_none(self):
        """Generic OS CPEs without version are filtered out (too noisy)."""
        result = _cpe22_to_23("cpe:/o:microsoft:windows")
        assert result is None

    def test_cpe22_os_esxi_with_version(self):
        """ESXi with specific version should be converted (high-value target)."""
        result = _cpe22_to_23("cpe:/o:vmware:ESXi:8.0.3")
        assert result == "cpe:2.3:o:vmware:esxi:8.0.3:*:*:*:*:*:*:*"

    def test_cpe22_os_cisco_ios_with_version(self):
        result = _cpe22_to_23("cpe:/o:cisco:ios:15.1")
        assert result == "cpe:2.3:o:cisco:ios:15.1:*:*:*:*:*:*:*"

    def test_cpe22_os_without_version_returns_none(self):
        """OS CPE without version should be None even for known products."""
        result = _cpe22_to_23("cpe:/o:vmware:esxi")
        assert result is None

    def test_cpe22_hardware_returns_none(self):
        result = _cpe22_to_23("cpe:/h:hp:laserjet")
        assert result is None

    def test_invalid_cpe_returns_none(self):
        assert _cpe22_to_23("not-a-cpe") is None
        assert _cpe22_to_23("cpe:/a:x") is None  # too few parts

    def test_vendor_correction_nginx(self):
        """Nmap's igor_sysoev:nginx should be corrected to f5:nginx."""
        result = _cpe22_to_23("cpe:/a:igor_sysoev:nginx:1.14.1")
        assert result == "cpe:2.3:a:f5:nginx:1.14.1:*:*:*:*:*:*:*"

    def test_vendor_correction_iis(self):
        """Nmap's internet_information_server should be corrected."""
        result = _cpe22_to_23("cpe:/a:microsoft:internet_information_server:10.0")
        assert result == "cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*"


class TestExtractVersion:
    def test_simple_version(self):
        assert _extract_version("2.4.49") == "2.4.49"

    def test_or_later(self):
        assert _extract_version("9.6.0 or later") == "9.6.0"

    def test_two_part_version(self):
        assert _extract_version("1.14") == "1.14"

    def test_range_not_parseable(self):
        """Version ranges like '2-4' should not be parsed."""
        assert _extract_version("2-4") == "*"

    def test_none(self):
        assert _extract_version(None) == "*"

    def test_empty(self):
        assert _extract_version("") == "*"

    def test_prefix_text(self):
        assert _extract_version("for_Windows_9.5") == "9.5"

    def test_complex(self):
        assert _extract_version("version 3.2.1-beta") == "3.2.1"


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

    @patch("cauldron.ai.cve_enricher._query_nvd_keyword")
    @patch("cauldron.ai.cve_enricher._query_nvd_cpe")
    def test_cpe_404_falls_back_to_keyword(self, mock_cpe, mock_kw, tmp_path: Path):
        """When CPE query returns None (404), should fall back to keyword search."""
        cache = CVECache(tmp_path / "cache.json")
        mock_cpe.return_value = None  # 404
        mock_kw.return_value = [CVEInfo(cve_id="CVE-2024-0001", cvss=9.0)]

        result = enrich_service("nginx", "1.14.1", cache, cpe_list=["cpe:/a:igor_sysoev:nginx:1.14.1"])
        mock_kw.assert_called_once_with("nginx", "1.14.1")
        assert len(result.cves) == 1

    @patch("cauldron.ai.cve_enricher._query_nvd_keyword")
    @patch("cauldron.ai.cve_enricher._query_nvd_cpe")
    def test_cpe_404_no_version_no_keyword(self, mock_cpe, mock_kw, tmp_path: Path):
        """When CPE 404 and no parseable version, no keyword search."""
        cache = CVECache(tmp_path / "cache.json")
        mock_cpe.return_value = None

        result = enrich_service("SomeProduct", "", cache, cpe_list=["cpe:/a:vendor:product"])
        mock_kw.assert_not_called()
        assert result.cves == []

    @patch("cauldron.ai.cve_enricher._query_nvd_cpe")
    def test_fuzzy_version_in_fallback(self, mock_cpe, tmp_path: Path):
        """PRODUCT_CPE_MAP fallback should extract version from fuzzy strings."""
        cache = CVECache(tmp_path / "cache.json")
        mock_cpe.return_value = []

        enrich_service("PostgreSQL", "9.6.0 or later", cache, cpe_list=[])
        mock_cpe.assert_called_once()
        call_args = mock_cpe.call_args[0][0]
        assert "postgresql:postgresql:9.6.0" in call_args


class TestParseCVEExtended:
    """Test CWE and published date extraction."""

    def test_parse_cwe_ids(self):
        cve_data = SAMPLE_CVE_RESPONSE["vulnerabilities"][0]["cve"]
        cve = _parse_cve(cve_data)
        assert cve is not None
        assert "CWE-22" in cve.cwe_ids

    def test_parse_multiple_cwes(self):
        cve_data = {
            "id": "CVE-2024-0001",
            "descriptions": [{"lang": "en", "value": "Test"}],
            "metrics": {},
            "references": [],
            "weaknesses": [
                {"description": [{"lang": "en", "value": "CWE-89"}]},
                {"description": [{"lang": "en", "value": "CWE-78"}]},
            ],
        }
        cve = _parse_cve(cve_data)
        assert cve is not None
        assert "CWE-89" in cve.cwe_ids
        assert "CWE-78" in cve.cwe_ids

    def test_parse_no_cwe(self):
        cve_data = {
            "id": "CVE-2024-0002",
            "descriptions": [{"lang": "en", "value": "Test"}],
            "metrics": {},
            "references": [],
        }
        cve = _parse_cve(cve_data)
        assert cve is not None
        assert cve.cwe_ids == []

    def test_parse_published_date(self):
        cve_data = SAMPLE_CVE_RESPONSE["vulnerabilities"][0]["cve"]
        cve = _parse_cve(cve_data)
        assert cve is not None
        assert cve.published == "2021-10-05T09:15:00.000"

    def test_cweinfo_roundtrip(self):
        """CWE IDs and published date survive serialization/deserialization."""
        cve = CVEInfo(
            cve_id="CVE-2024-0001",
            cvss=8.0,
            cwe_ids=["CWE-78", "CWE-94"],
            published="2024-01-15T10:00:00.000",
        )
        d = cve.to_dict()
        cve2 = CVEInfo.from_dict(d)
        assert cve2.cwe_ids == ["CWE-78", "CWE-94"]
        assert cve2.published == "2024-01-15T10:00:00.000"


class TestPentesterRelevance:
    """Test the pentester-relevant filter logic."""

    def test_exploit_always_relevant(self):
        cve = CVEInfo(cve_id="CVE-2024-0001", cvss=3.0, has_exploit=True)
        assert _is_pentester_relevant(cve) is True

    def test_rce_cwe_relevant(self):
        cve = CVEInfo(cve_id="CVE-2024-0001", cvss=6.0, cwe_ids=["CWE-78"])
        assert _is_pentester_relevant(cve) is True

    def test_auth_bypass_cwe_relevant(self):
        cve = CVEInfo(cve_id="CVE-2024-0001", cvss=6.5, cwe_ids=["CWE-287"])
        assert _is_pentester_relevant(cve) is True

    def test_sqli_cwe_relevant(self):
        cve = CVEInfo(cve_id="CVE-2024-0001", cvss=6.0, cwe_ids=["CWE-89"])
        assert _is_pentester_relevant(cve) is True

    def test_ssrf_cwe_relevant(self):
        cve = CVEInfo(cve_id="CVE-2024-0001", cvss=5.0, cwe_ids=["CWE-918"])
        assert _is_pentester_relevant(cve) is True

    def test_deserialization_cwe_relevant(self):
        cve = CVEInfo(cve_id="CVE-2024-0001", cvss=6.0, cwe_ids=["CWE-502"])
        assert _is_pentester_relevant(cve) is True

    def test_path_traversal_cwe_relevant(self):
        cve = CVEInfo(cve_id="CVE-2024-0001", cvss=5.5, cwe_ids=["CWE-22"])
        assert _is_pentester_relevant(cve) is True

    def test_file_upload_cwe_relevant(self):
        cve = CVEInfo(cve_id="CVE-2024-0001", cvss=6.0, cwe_ids=["CWE-434"])
        assert _is_pentester_relevant(cve) is True

    def test_network_rce_vector_relevant(self):
        """Network-accessible, no auth, high impact — RCE territory."""
        cve = CVEInfo(
            cve_id="CVE-2024-0001",
            cvss=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        assert _is_pentester_relevant(cve) is True

    def test_local_only_not_relevant(self):
        """Local-only, no exploit, no CWE, medium CVSS — not useful for remote pentest."""
        cve = CVEInfo(
            cve_id="CVE-2024-0001",
            cvss=6.5,
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N",
        )
        assert _is_pentester_relevant(cve) is False

    def test_dos_not_relevant(self):
        """DoS with high CVSS but no exploit, no relevant CWE, no keywords."""
        cve = CVEInfo(
            cve_id="CVE-2024-0001",
            cvss=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            description="Denial of service via crafted packet causes crash.",
            cwe_ids=["CWE-400"],  # Not in pentester set
        )
        assert _is_pentester_relevant(cve) is False

    def test_description_rce_keyword_relevant(self):
        cve = CVEInfo(
            cve_id="CVE-2024-0001",
            cvss=6.0,
            description="A remote code execution vulnerability exists in the API.",
        )
        assert _is_pentester_relevant(cve) is True

    def test_description_auth_bypass_keyword_relevant(self):
        cve = CVEInfo(
            cve_id="CVE-2024-0001",
            cvss=5.0,
            description="An authentication bypass allows unauthenticated access.",
        )
        assert _is_pentester_relevant(cve) is True

    def test_description_deserialization_keyword(self):
        cve = CVEInfo(
            cve_id="CVE-2024-0001",
            cvss=6.0,
            description="Unsafe deserialization in the SOAP handler leads to code execution.",
        )
        assert _is_pentester_relevant(cve) is True

    def test_critical_cvss_safety_net(self):
        """CVSS >= 9.0 is always kept as safety net even without other signals."""
        cve = CVEInfo(
            cve_id="CVE-2024-0001",
            cvss=9.5,
            description="Something very bad happens.",
        )
        assert _is_pentester_relevant(cve) is True

    def test_medium_cvss_no_signals_not_relevant(self):
        """Medium CVSS with no exploit, no CWE, no keywords — filtered out."""
        cve = CVEInfo(
            cve_id="CVE-2024-0001",
            cvss=6.5,
            description="Information disclosure via timing attack.",
            cwe_ids=["CWE-203"],
        )
        assert _is_pentester_relevant(cve) is False

    def test_xss_not_relevant(self):
        """XSS is not pentester-relevant for network engagement."""
        cve = CVEInfo(
            cve_id="CVE-2024-0001",
            cvss=6.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            description="Cross-site scripting in the admin panel.",
            cwe_ids=["CWE-79"],
        )
        assert _is_pentester_relevant(cve) is False

    def test_info_disclosure_low_cvss_not_relevant(self):
        cve = CVEInfo(
            cve_id="CVE-2024-0001",
            cvss=4.3,
            description="Server exposes internal IP addresses in HTTP headers.",
        )
        assert _is_pentester_relevant(cve) is False


class TestCVEMatchesProduct:
    """Test product validation for keyword search results."""

    def test_matches_via_cpe_configurations(self):
        cve_data = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
                            ]
                        }
                    ]
                }
            ],
            "descriptions": [{"lang": "en", "value": "Test"}],
        }
        assert _cve_matches_product(cve_data, "apache") is True
        assert _cve_matches_product(cve_data, "http_server") is True

    def test_no_match_wrong_product(self):
        cve_data = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": "cpe:2.3:a:oracle:mysql:8.0.25:*:*:*:*:*:*:*"}
                            ]
                        }
                    ]
                }
            ],
            "descriptions": [{"lang": "en", "value": "Test"}],
        }
        assert _cve_matches_product(cve_data, "apache") is False

    def test_matches_product_with_spaces(self):
        """Product names with spaces should match CPE underscored format."""
        cve_data = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
                            ]
                        }
                    ]
                }
            ],
            "descriptions": [{"lang": "en", "value": "Test"}],
        }
        assert _cve_matches_product(cve_data, "http server") is True

    def test_fallback_to_description_when_no_configs(self):
        """Without CPE configs, check description for product name."""
        cve_data = {
            "configurations": [],
            "descriptions": [{"lang": "en", "value": "Vulnerability in OpenSSH allows..."}],
        }
        assert _cve_matches_product(cve_data, "openssh") is True

    def test_fallback_description_no_match(self):
        cve_data = {
            "configurations": [],
            "descriptions": [{"lang": "en", "value": "Vulnerability in MySQL allows..."}],
        }
        assert _cve_matches_product(cve_data, "openssh") is False

    def test_no_configs_no_descriptions(self):
        cve_data = {}
        assert _cve_matches_product(cve_data, "anything") is False


class TestExecuteNVDRetry:
    """Test that 403 retries are capped at 2."""

    @patch("cauldron.ai.cve_enricher.settings")
    @patch("cauldron.ai.cve_enricher.urllib.request.urlopen")
    @patch("cauldron.ai.cve_enricher._rate_limit")
    @patch("cauldron.ai.cve_enricher.time.sleep")
    def test_403_retries_capped(self, mock_sleep, mock_rate, mock_urlopen, mock_settings):
        """Persistent 403 should retry max 2 times, not recurse infinitely."""
        from cauldron.ai.cve_enricher import _execute_nvd_query

        mock_settings.nvd_api_key = None
        mock_urlopen.side_effect = urllib_403_error()

        result = _execute_nvd_query("https://example.com", "test")
        assert result == []
        # 2 retries after initial attempt = 2 sleeps
        assert mock_sleep.call_count == 2


def urllib_403_error():
    """Create a sequence of 403 errors for testing."""
    import urllib.error
    for _ in range(3):
        yield urllib.error.HTTPError("https://nvd.nist.gov", 403, "Forbidden", {}, None)
