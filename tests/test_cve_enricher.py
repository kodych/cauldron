"""Tests for CVE enricher.

Uses mocked NVD API responses to avoid real API calls during testing.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from cauldron.graph.connection import clear_database, get_session, verify_connection

from cauldron.ai.cve_enricher import (
    CVECache,
    CVEInfo,
    PRODUCT_CPE_MAP,
    _cpe22_to_23,
    _cve_applies_to,
    _cve_is_dos_only,
    _cve_is_gold,
    _cve_is_local_only,
    _cve_matches_product,
    _cve_priority_key,
    _cve_requires_admin,
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


class TestCPEBuildPartType:
    """Root fix: _build_cpe23 must pick OS part type for products NVD
    registers as operating systems, otherwise wildcard application-typed
    queries return zero matches for ESXi/MikroTik/PAN-OS/FortiOS."""

    def test_app_product_uses_a_type(self):
        from cauldron.ai.cve_enricher import _build_cpe23
        cpe = _build_cpe23("apache", "http_server", "2.4.49")
        assert cpe.startswith("cpe:2.3:a:")

    def test_os_product_uses_o_type(self):
        from cauldron.ai.cve_enricher import _build_cpe23
        cpe = _build_cpe23("vmware", "esxi", "7.0")
        assert cpe.startswith("cpe:2.3:o:")

    def test_mikrotik_routeros_uses_o_type(self):
        from cauldron.ai.cve_enricher import _build_cpe23
        cpe = _build_cpe23("mikrotik", "routeros", "7.5")
        assert cpe.startswith("cpe:2.3:o:")


class TestCPEPrefixMatch:
    """Root fix: nmap appends service suffixes to canonical product names
    (e.g. 'VMware ESXi Server httpd'). The CPE lookup must still resolve
    via prefix to the base 'vmware esxi' entry."""

    def test_suffix_extended_product_resolves(self):
        result = _get_cpe_for_service([], "VMware ESXi Server httpd", None)
        assert result is not None
        assert "vmware:esxi" in result

    def test_soap_api_suffix_resolves(self):
        result = _get_cpe_for_service([], "VMware vCenter Server SOAP API", "7.0.3")
        assert result is not None
        assert "vmware:vcenter_server:7.0.3" in result

    def test_unrelated_prefix_does_not_match(self):
        # 'SomeProduct' is not a prefix of anything in the map
        result = _get_cpe_for_service([], "SomeProduct server", "1.0")
        assert result is None


class TestCPEVersionRelaxation:
    """Root fix: NVD pins CVEs to major versions for some vendors (e.g.
    vcenter_server:7.0) while nmap reports patch levels (7.0.3). When a
    specific-version query returns zero CVEs, retry with version=*."""

    def test_relax_removes_version(self):
        from cauldron.ai.cve_enricher import _relax_cpe_version
        relaxed = _relax_cpe_version("cpe:2.3:a:vmware:vcenter_server:7.0.3:*:*:*:*:*:*:*")
        assert relaxed == "cpe:2.3:a:vmware:vcenter_server:*:*:*:*:*:*:*:*"

    def test_relax_wildcard_returns_none(self):
        from cauldron.ai.cve_enricher import _relax_cpe_version
        assert _relax_cpe_version("cpe:2.3:a:foo:bar:*:*:*:*:*:*:*:*") is None

    def test_relax_invalid_cpe_returns_none(self):
        from cauldron.ai.cve_enricher import _relax_cpe_version
        assert _relax_cpe_version("not-a-cpe") is None

    @patch("cauldron.ai.cve_enricher._query_nvd_cpe")
    def test_specific_version_empty_triggers_retry(self, mock_cpe, tmp_path: Path):
        """Empty result on specific version must trigger one wildcard retry."""
        cache = CVECache(tmp_path / "cache.json")
        mock_cpe.return_value = []

        enrich_service("OpenSSH", "7.4", cache, cpe_list=[])
        assert mock_cpe.call_count == 2
        assert "openssh:7.4:" in mock_cpe.call_args_list[0][0][0]
        assert "openssh:*:" in mock_cpe.call_args_list[1][0][0]

    @patch("cauldron.ai.cve_enricher._query_nvd_cpe")
    def test_wildcard_version_no_retry(self, mock_cpe, tmp_path: Path):
        """Wildcard version already — no retry even when result is empty."""
        cache = CVECache(tmp_path / "cache.json")
        mock_cpe.return_value = []

        enrich_service("OpenSSH", None, cache, cpe_list=[])
        assert mock_cpe.call_count == 1


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
        # First call uses the nmap-provided version; empty result triggers a
        # wildcard-version retry (second call).
        assert mock_cpe_query.call_count >= 1
        first_call = mock_cpe_query.call_args_list[0][0][0]
        assert "openbsd:openssh:7.4" in first_call

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
    def test_cpe_404_versionless_falls_back_to_keyword(self, mock_cpe, mock_kw, tmp_path: Path):
        """When CPE returns 404 with no version, keyword search still fires —
        the three-rule strategy keeps rule #3 (service-only) working when NVD
        doesn't recognize the wildcard CPE."""
        cache = CVECache(tmp_path / "cache.json")
        mock_cpe.return_value = None
        mock_kw.return_value = []

        enrich_service("SomeProduct", "", cache, cpe_list=["cpe:/a:vendor:product"])
        mock_kw.assert_called_once()

    @patch("cauldron.ai.cve_enricher._query_nvd_cpe")
    def test_fuzzy_version_in_fallback(self, mock_cpe, tmp_path: Path):
        """PRODUCT_CPE_MAP fallback should extract version from fuzzy strings."""
        cache = CVECache(tmp_path / "cache.json")
        mock_cpe.return_value = []

        enrich_service("PostgreSQL", "9.6.0 or later", cache, cpe_list=[])
        # Empty result triggers the wildcard-version retry.
        assert mock_cpe.call_count >= 1
        first_call = mock_cpe.call_args_list[0][0][0]
        assert "postgresql:postgresql:9.6.0" in first_call

    @patch("cauldron.ai.cve_enricher._query_nvd_cpe")
    def test_wildcard_retry_threads_service_version(self, mock_cpe, tmp_path: Path):
        """When a specific-version CPE returns empty and we relax to a
        wildcard version, the original service version must be threaded
        through to the follow-up query. Without this the applicability
        filter falls into the "versionless" branch and drops every modern
        vendor CVE pinned to a specific major.minor — the bug class that
        hides CVE-2024-37085 (ESXi KEV) on real enterprise scans where
        the deployed patch level never matches the vendor's major.minor.
        """
        cache = CVECache(tmp_path / "cache.json")
        # First call (specific version) returns empty; second (relaxed)
        # returns a stub CVE. We assert both the CPE strings and the
        # version override argument the enricher passes on the retry.
        mock_cpe.side_effect = [[], [CVEInfo(cve_id="CVE-2024-37085", cvss=6.8)]]

        result = enrich_service(
            "VMware ESXi SOAP API", "8.0.3", cache,
            cpe_list=["cpe:/o:vmware:ESXi:8.0.3"],
        )
        assert len(result.cves) == 1
        assert result.cves[0].cve_id == "CVE-2024-37085"
        assert mock_cpe.call_count == 2
        # First call: specific version, no override.
        first_args, first_kwargs = mock_cpe.call_args_list[0]
        assert "vmware:esxi:8.0.3" in first_args[0]
        # Second call: wildcard CPE, original version threaded via kwarg.
        second_args, second_kwargs = mock_cpe.call_args_list[1]
        assert "vmware:esxi:*" in second_args[0]
        assert second_kwargs.get("service_version_override") == "8.0.3"


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
        cve = CVEInfo(cve_id="CVE-2024-0001", cvss=7.0, cwe_ids=["CWE-918"])
        assert _is_pentester_relevant(cve) is True

    def test_deserialization_cwe_relevant(self):
        cve = CVEInfo(cve_id="CVE-2024-0001", cvss=6.0, cwe_ids=["CWE-502"])
        assert _is_pentester_relevant(cve) is True

    def test_path_traversal_cwe_relevant(self):
        cve = CVEInfo(cve_id="CVE-2024-0001", cvss=6.5, cwe_ids=["CWE-22"])
        assert _is_pentester_relevant(cve) is True

    def test_cwe_below_threshold_dropped(self):
        """CWE match with CVSS < 6.0 is filtered out as trivial."""
        cve = CVEInfo(cve_id="CVE-2024-0001", cvss=3.7, cwe_ids=["CWE-287"])
        assert _is_pentester_relevant(cve) is False

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


class TestCVEIsGold:
    """Actionable-gold filter — single strict rule: keep only CVEs with a
    public exploit. Version applicability is enforced upstream by
    ``_cve_applies_to``; when no version is known, we assume the service
    runs the latest release and keep the CVEs an operator could actually
    run against it. CISA KEV overrides the has_exploit gate (actively
    exploited in the wild beats every heuristic) but not the hard rejects
    (local/physical vector, pure DoS, admin-required). This is deliberately
    stricter than a CVSS-based rule — "theoretical critical" CVEs without
    any PoC were the dominant noise pattern on real client scans, with
    dozens of Apache/Samba 9.x CVEs bulk-attaching to every host.
    """

    def _cve(
        self,
        cvss: float = 7.5,
        has_exploit: bool = False,
        vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        in_cisa_kev: bool = False,
    ) -> CVEInfo:
        return CVEInfo(
            cve_id="CVE-TEST-0001",
            cvss=cvss,
            cvss_vector=vector,
            has_exploit=has_exploit,
            in_cisa_kev=in_cisa_kev,
        )

    # --- Hard rejects ---

    def test_local_vector_dropped_even_with_exploit(self):
        cve = self._cve(cvss=9.8, has_exploit=True,
                        vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert _cve_is_gold(cve) is False

    def test_physical_vector_dropped(self):
        cve = self._cve(cvss=9.0, has_exploit=True,
                        vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert _cve_is_gold(cve) is False

    def test_dos_only_dropped(self):
        cve = self._cve(cvss=9.8, has_exploit=True,
                        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
        assert _cve_is_gold(cve) is False

    def test_admin_required_dropped(self):
        """PR:H means the attacker already has an admin shell — post-ex, not a way in."""
        cve = self._cve(cvss=9.8, has_exploit=True,
                        vector="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")
        assert _cve_requires_admin(cve) is True
        assert _cve_is_gold(cve) is False

    # --- Core rule: has_exploit required ---

    def test_has_exploit_kept_even_at_low_cvss(self):
        """Exploit code exists → pentester can run it → keep regardless of CVSS."""
        cve = self._cve(cvss=5.0, has_exploit=True)
        assert _cve_is_gold(cve) is True

    def test_no_exploit_high_cvss_dropped(self):
        """CVSS 9.8 without any PoC is theoretical noise — drop.

        Regression guard for the bulk-attach pattern: Apache 2.4 NVD
        dumps fifteen CVSS 9.x CVEs per host with no public exploit,
        turning every web server into a Christmas tree of unusable
        findings.
        """
        cve = self._cve(cvss=9.8, has_exploit=False)
        assert _cve_is_gold(cve) is False

    def test_no_exploit_cvss_7_dropped(self):
        cve = self._cve(cvss=7.5, has_exploit=False)
        assert _cve_is_gold(cve) is False

    def test_old_cve_kept_if_has_exploit(self):
        """No recency gate — an ancient CVE with a working Metasploit
        module is still usable on a legacy host."""
        cve = self._cve(cvss=9.0, has_exploit=True)
        assert _cve_is_gold(cve) is True

    # --- Vector-parser edge cases ---

    def test_missing_vector_does_not_trigger_local_reject(self):
        """A CVE with no vector string should pass the local/DoS gates."""
        cve = self._cve(cvss=9.8, has_exploit=True, vector=None)
        assert _cve_is_local_only(cve) is False
        assert _cve_is_dos_only(cve) is False
        assert _cve_is_gold(cve) is True

    def test_dos_with_integrity_loss_kept(self):
        """Mixed impact (I:L + A:H) is NOT pure DoS — keep if has_exploit."""
        cve = self._cve(cvss=8.2, has_exploit=True,
                        vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H")
        assert _cve_is_dos_only(cve) is False
        assert _cve_is_gold(cve) is True

    def test_pr_low_kept_if_has_exploit(self):
        """Low-priv (PR:L) requirement is still exploitable post-initial-access."""
        cve = self._cve(cvss=8.0, has_exploit=True,
                        vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        assert _cve_requires_admin(cve) is False
        assert _cve_is_gold(cve) is True

    def test_pr_none_without_exploit_dropped(self):
        """Even unauth CVEs need a PoC to count as gold under the new rule."""
        cve = self._cve(cvss=7.5, has_exploit=False,
                        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert _cve_is_gold(cve) is False

    # --- CISA KEV override ---

    def test_kev_overrides_missing_exploit(self):
        """KEV-listed CVE kept even without NVD-tagged exploit — CISA itself
        is confirming active in-the-wild exploitation."""
        cve = self._cve(cvss=4.5, has_exploit=False, in_cisa_kev=True)
        assert _cve_is_gold(cve) is True

    def test_kev_does_not_override_local(self):
        """Even KEV doesn't help on a network scan if vector is local-only."""
        cve = self._cve(cvss=9.8, has_exploit=True, in_cisa_kev=True,
                        vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert _cve_is_gold(cve) is False

    def test_kev_does_not_override_dos_only(self):
        """CVE-2023-44487 (HTTP/2 Rapid Reset) — KEV but pure DoS.
        Attack-in-the-wild yes, pentest gold on a netscan no."""
        cve = self._cve(cvss=7.5, has_exploit=True, in_cisa_kev=True,
                        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
        assert _cve_is_gold(cve) is False

    # --- Versionless "assume latest" recency cut ---

    def _cve_with_year(self, year: int, **kwargs) -> CVEInfo:
        return CVEInfo(
            cve_id=f"CVE-{year}-0001",
            cvss=kwargs.get("cvss", 9.8),
            cvss_vector=kwargs.get(
                "vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            has_exploit=kwargs.get("has_exploit", True),
            in_cisa_kev=kwargs.get("in_cisa_kev", False),
            published=f"{year}-01-01T00:00:00.000",
        )

    def test_versionless_drops_ancient_has_exploit_cve(self):
        """With no version anchor, we assume the service runs the latest
        release. An exploit-db entry from 2003 targets Apache 1.3 — it has
        a PoC on file but does not apply to a modern install. This is the
        regression the Apache 37-host scan surfaced: relaxing the version
        filter exposed CVE-2003-0132, CVE-2004-0809, CVE-2005-2088, etc.
        """
        ancient = self._cve_with_year(2005, has_exploit=True)
        assert _cve_is_gold(ancient, versionless=True) is False

    def test_versionless_keeps_recent_has_exploit(self):
        recent = self._cve_with_year(2024, has_exploit=True)
        assert _cve_is_gold(recent, versionless=True) is True

    def test_versionless_kev_overrides_recency(self):
        """KEV beats the recency cut — actively exploited in the wild is
        a stronger signal than an old publication date (SambaCry 2017)."""
        ancient_kev = self._cve_with_year(
            2017, has_exploit=True, in_cisa_kev=True)
        assert _cve_is_gold(ancient_kev, versionless=True) is True

    def test_versioned_does_not_apply_recency(self):
        """When we have a service version, range matching upstream already
        proved applicability — no need for a recency proxy. An old CVE
        with an exploit on a legacy host (OpenSSH 6.x) is real gold."""
        old = self._cve_with_year(2014, has_exploit=True)
        assert _cve_is_gold(old, versionless=False) is True
        assert _cve_is_gold(old) is True  # default is versioned

    def test_versionless_missing_publish_date_treated_as_recent(self):
        """Defensive — don't over-filter on absent publication date."""
        cve = CVEInfo(
            cve_id="CVE-X-0001",
            cvss=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            has_exploit=True,
            published=None,
        )
        assert _cve_is_gold(cve, versionless=True) is True

    # --- Priority sort: KEV first, then exploit, then CVSS ---

    def test_priority_sort_kev_beats_exploit(self):
        kev = CVEInfo(cve_id="K", cvss=5.0, in_cisa_kev=True)
        exp = CVEInfo(cve_id="E", cvss=9.8, has_exploit=True)
        ordered = sorted([exp, kev], key=_cve_priority_key)
        assert ordered[0].cve_id == "K"

    def test_priority_sort_exploit_beats_higher_cvss(self):
        no_exp_high = CVEInfo(cve_id="N", cvss=9.8)
        exp_low = CVEInfo(cve_id="E", cvss=7.0, has_exploit=True)
        ordered = sorted([no_exp_high, exp_low], key=_cve_priority_key)
        assert ordered[0].cve_id == "E"

    def test_priority_sort_cvss_breaks_tie(self):
        a = CVEInfo(cve_id="A", cvss=7.5, has_exploit=True)
        b = CVEInfo(cve_id="B", cvss=9.0, has_exploit=True)
        ordered = sorted([a, b], key=_cve_priority_key)
        assert ordered[0].cve_id == "B"


class TestKEVParsing:
    """Verify cisaExploitAdd is parsed off the NVD response into CVEInfo."""

    def test_cisa_exploit_add_parsed(self):
        cve_data = {
            "id": "CVE-2024-9999",
            "descriptions": [{"lang": "en", "value": "Test"}],
            "metrics": {},
            "references": [],
            "cisaExploitAdd": "2024-09-15",
        }
        cve = _parse_cve(cve_data)
        assert cve is not None
        assert cve.in_cisa_kev is True
        assert cve.cisa_kev_added == "2024-09-15"

    def test_no_kev_field_parses_false(self):
        cve_data = {
            "id": "CVE-2024-0001",
            "descriptions": [{"lang": "en", "value": "Test"}],
            "metrics": {},
            "references": [],
        }
        cve = _parse_cve(cve_data)
        assert cve is not None
        assert cve.in_cisa_kev is False
        assert cve.cisa_kev_added is None


class TestCVEAppliesTo:
    """Version-applicability filter — the mechanism that drops 1999 CVEs
    pinned to ``apache:http_server:1.0.3`` from attaching to modern Apache."""

    # Ancient CVE: pinned to a specific old version, no version range
    ANCIENT_CVE = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [
                    {"criteria": "cpe:2.3:a:apache:http_server:1.0.3:*:*:*:*:*:*:*"}
                ]
            }]
        }]
    }

    # Modern CVE with explicit range
    RANGED_CVE = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [{
                    "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                    "versionStartIncluding": "2.4.49",
                    "versionEndExcluding": "2.4.52",
                }]
            }]
        }]
    }

    # CVE with fully unconstrained CPE (wildcard version, no range)
    UNCONSTRAINED_CVE = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [
                    {"criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"}
                ]
            }]
        }]
    }

    NO_CONFIG_CVE = {"configurations": []}

    # --- Versionless service (wildcard CPE query) ---

    def test_versionless_drops_pinned_ancient_cve(self):
        """Apache httpd with no version: CVE pinned to 1.0.3 must drop."""
        assert _cve_applies_to(self.ANCIENT_CVE, "http_server", None) is False

    def test_versionless_keeps_range_bounded_cve(self):
        """Versionless service: range-bounded CVEs are kept because they
        came from NVD with an explicit applicability window — the modern
        vendor-CVE pattern. Ancient phantom CVEs pin a bare version with
        no range (see `test_versionless_drops_pinned_ancient_cve`).

        Regression guard for the bug where CVE-2024-4040 (CrushFTP, range
        10.0.0–10.7.1) and CVE-2024-37085 (ESXi) were being eaten by the
        previous "unconstrained only" rule when the service had no known
        version or the CPE was relaxed to a wildcard on retry. Recency
        and severity are handled downstream by `_cve_is_gold`.
        """
        assert _cve_applies_to(self.RANGED_CVE, "http_server", None) is True

    def test_versionless_keeps_unconstrained_cve(self):
        """CVE with wildcard CPE applies to any version — keep."""
        assert _cve_applies_to(self.UNCONSTRAINED_CVE, "http_server", None) is True

    def test_no_config_passes_through(self):
        """CVEs without CPE configurations aren't filtered here."""
        assert _cve_applies_to(self.NO_CONFIG_CVE, "http_server", None) is True

    # --- Versioned service ---

    def test_versioned_in_range_keeps(self):
        assert _cve_applies_to(self.RANGED_CVE, "http_server", "2.4.50") is True

    def test_versioned_below_range_drops(self):
        assert _cve_applies_to(self.RANGED_CVE, "http_server", "2.4.48") is False

    def test_versioned_at_end_exclusive_drops(self):
        assert _cve_applies_to(self.RANGED_CVE, "http_server", "2.4.52") is False

    def test_versioned_pinned_same_major_minor_keeps(self):
        """CVE pinned at 1.0.3; service reports 1.0.9 — same major.minor → keep."""
        assert _cve_applies_to(self.ANCIENT_CVE, "http_server", "1.0.9") is True

    def test_versioned_pinned_different_major_drops(self):
        """Modern Apache 2.4.x versus 1999 CVE pinned at 1.0.3 — must drop."""
        assert _cve_applies_to(self.ANCIENT_CVE, "http_server", "2.4.51") is False

    def test_versioned_unconstrained_keeps(self):
        assert _cve_applies_to(self.UNCONSTRAINED_CVE, "http_server", "2.4.51") is True

    # --- Edge cases ---

    def test_unparseable_version_treated_as_versionless(self):
        """A version string nmap couldn't parse behaves like "no version" —
        range-bounded and unconstrained CVEs both pass, because with no
        anchor we cannot verify the range but the range is a real
        applicability window we trust. Recency and severity are enforced
        downstream by `_cve_is_gold`.
        """
        assert _cve_applies_to(self.RANGED_CVE, "http_server", "unknown-build-xyz") is True
        assert _cve_applies_to(self.UNCONSTRAINED_CVE, "http_server", "unknown-build-xyz") is True

    def test_other_product_ignored(self):
        """Product not referenced in CVE's CPE config — filter is neutral."""
        assert _cve_applies_to(self.ANCIENT_CVE, "nginx", "1.24.0") is True

    def test_vendor_pinned_major_minor_kept_when_matches(self):
        """VMware ESXi registers each patch release as a pinned CPE entry
        (e.g. ``esxi:8.0:a:*``) with no explicit range. When the service is
        ESXi 8.0.3 the wildcard-retry path threads that version back through
        so the filter can do major.minor matching — otherwise flagship CVEs
        like CVE-2024-37085 (CISA KEV) never attach to modern ESXi hosts.
        """
        esxi_pinned_cve = {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [
                        {"criteria": "cpe:2.3:o:vmware:esxi:8.0:-:*:*:*:*:*:*"},
                        {"criteria": "cpe:2.3:o:vmware:esxi:8.0:a:*:*:*:*:*:*"},
                        {"criteria": "cpe:2.3:o:vmware:esxi:7.0:*:*:*:*:*:*:*"},
                    ]
                }]
            }]
        }
        # 8.0.3 matches the 8.0:a pinned entry at major.minor level.
        assert _cve_applies_to(esxi_pinned_cve, "esxi", "8.0.3") is True
        # 6.5 deploy — no 6.5 entry in this CVE, must drop.
        assert _cve_applies_to(esxi_pinned_cve, "esxi", "6.5.0") is False

    def test_range_bounded_cve_kept_for_unknown_version(self):
        """CrushFTP services rarely expose a version — nmap reports
        ``CrushFTP sftpd`` with no version field. The wildcard CPE query
        returns range-bounded CVEs like CVE-2024-4040
        (``versionStartIncluding=10.0.0 versionEndExcluding=10.7.1``).
        Those must survive the applicability filter so flagship KEV CVEs
        land on the service even without a version anchor.
        """
        crushftp_ranged_cve = {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "criteria": "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "10.0.0",
                        "versionEndExcluding": "10.7.1",
                    }]
                }]
            }]
        }
        assert _cve_applies_to(crushftp_ranged_cve, "crushftp", None) is True
        # And when we DO know the version, range matching still works.
        assert _cve_applies_to(crushftp_ranged_cve, "crushftp", "10.3.0") is True
        assert _cve_applies_to(crushftp_ranged_cve, "crushftp", "10.7.1") is False

    def test_na_marker_treated_as_unverifiable(self):
        """NVD sometimes tags CVEs with CPE version = '-' (Not Applicable).
        These are legacy / broken entries where we cannot confirm the CVE
        actually affects the running version — drop to avoid phantom hits
        like CVE-1999-1237 tagged at 'apache:http_server:-'."""
        cve = {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [
                        {"criteria": "cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*"}
                    ]
                }]
            }]
        }
        assert _cve_applies_to(cve, "http_server", None) is False
        assert _cve_applies_to(cve, "http_server", "2.4.51") is False

    def test_multiple_cpe_any_match_keeps(self):
        """If at least one CPE entry applies, the CVE is kept."""
        cve = {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [
                        {"criteria": "cpe:2.3:a:apache:http_server:1.0.3:*:*:*:*:*:*:*"},
                        {
                            "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "2.4.0",
                            "versionEndExcluding": "2.4.60",
                        },
                    ]
                }]
            }]
        }
        assert _cve_applies_to(cve, "http_server", "2.4.51") is True


class TestExecuteNVDRetry:
    """Retries are capped and exhaustion raises NvdTransientError.

    Raising (instead of returning []) is the whole point of the
    transient-vs-authoritative distinction: a failed query is not the
    same as "NVD said zero CVEs" and must not poison the 7-day cache.
    """

    @patch("cauldron.ai.cve_enricher.settings")
    @patch("cauldron.ai.cve_enricher.urllib.request.urlopen")
    @patch("cauldron.ai.cve_enricher._rate_limit")
    @patch("cauldron.ai.cve_enricher.time.sleep")
    def test_403_retries_capped_then_raises(self, mock_sleep, mock_rate, mock_urlopen, mock_settings):
        import pytest

        from cauldron.ai.cve_enricher import NvdTransientError, _execute_nvd_query

        mock_settings.nvd_api_key = None
        mock_urlopen.side_effect = urllib_403_error()

        with pytest.raises(NvdTransientError):
            _execute_nvd_query("https://example.com", "test")
        assert mock_sleep.call_count == 3

    @patch("cauldron.ai.cve_enricher.settings")
    @patch("cauldron.ai.cve_enricher.urllib.request.urlopen")
    @patch("cauldron.ai.cve_enricher._rate_limit")
    @patch("cauldron.ai.cve_enricher.time.sleep")
    def test_transient_network_error_raises(self, mock_sleep, mock_rate, mock_urlopen, mock_settings):
        """URLError / OSError / JSONDecodeError after retries raises."""
        import urllib.error

        import pytest

        from cauldron.ai.cve_enricher import NvdTransientError, _execute_nvd_query

        mock_settings.nvd_api_key = None
        mock_urlopen.side_effect = urllib.error.URLError("Connection timed out")

        with pytest.raises(NvdTransientError):
            _execute_nvd_query("https://example.com", "test")
        assert mock_sleep.call_count == 3

    @patch("cauldron.ai.cve_enricher.settings")
    @patch("cauldron.ai.cve_enricher.urllib.request.urlopen")
    @patch("cauldron.ai.cve_enricher._rate_limit")
    def test_404_still_returns_none(self, mock_rate, mock_urlopen, mock_settings):
        """404 remains the keyword-fallback signal — not a transient error."""
        import urllib.error

        from cauldron.ai.cve_enricher import _execute_nvd_query

        mock_settings.nvd_api_key = None
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://nvd.nist.gov", 404, "Not Found", {}, None,
        )

        result = _execute_nvd_query("https://example.com", "test")
        assert result is None


class TestTransientErrorDoesNotPoisonCache:
    """Transient NVD outage must NOT write an empty-list cache entry.

    Before this guard, a failed query cached ``[]`` for 7 days, which meant
    the next six boils would silently report zero CVEs for every affected
    service without ever retrying.
    """

    @patch("cauldron.ai.cve_enricher.settings")
    @patch("cauldron.ai.cve_enricher.urllib.request.urlopen")
    @patch("cauldron.ai.cve_enricher._rate_limit")
    @patch("cauldron.ai.cve_enricher.time.sleep")
    def test_network_failure_skips_cache(
        self, mock_sleep, mock_rate, mock_urlopen, mock_settings, tmp_path,
    ):
        import urllib.error

        from cauldron.ai.cve_enricher import CVECache, enrich_service

        mock_settings.nvd_api_key = None
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        cache_file = tmp_path / "cache.json"
        cache = CVECache(cache_file=cache_file)

        result = enrich_service("Apache httpd", "2.4.49", cache=cache)

        # Error surface to caller — not silent empty list
        assert result.error is not None
        assert "transient" in result.error.lower()
        assert result.cves == []

        # Critical: nothing written to cache, so next run will retry
        assert cache.size == 0

class TestEPSSFetchAndCache:
    """Regression: the CVEInfo.epss field was declared but never populated.
    enrich_epss_from_graph must fetch scores from FIRST.org, cache them
    with the 24h TTL, and write v.epss on matching Vulnerability nodes.
    Only real CVE-* IDs are eligible; CAULDRON-* synthetic IDs are
    skipped because FIRST.org only scores real CVEs.
    """

    def _epss_response(self, scores: dict[str, str]):
        """Build a mock FIRST.org response body."""
        import json as _json
        from unittest.mock import MagicMock as _MagicMock
        body = _json.dumps({
            "status": "OK",
            "data": [{"cve": cid, "epss": val, "percentile": "0.5",
                      "date": "2026-04-24"}
                     for cid, val in scores.items()],
        }).encode()
        mock = _MagicMock()
        mock.read.return_value = body
        return mock

    @patch("cauldron.ai.cve_enricher.urllib.request.urlopen")
    def test_fetch_batch_parses_scores(self, mock_urlopen):
        from cauldron.ai.cve_enricher import _fetch_epss_batch

        mock_urlopen.return_value = self._epss_response({
            "CVE-2021-41773": "0.97351",
            "CVE-2020-1472": "0.94120",
        })

        scores = _fetch_epss_batch(["CVE-2021-41773", "CVE-2020-1472"])

        assert scores == pytest.approx({
            "CVE-2021-41773": 0.97351,
            "CVE-2020-1472": 0.94120,
        })

    @patch("cauldron.ai.cve_enricher.urllib.request.urlopen")
    def test_fetch_empty_cve_list_short_circuits(self, mock_urlopen):
        from cauldron.ai.cve_enricher import _fetch_epss_batch

        assert _fetch_epss_batch([]) == {}
        mock_urlopen.assert_not_called()

    @patch("cauldron.ai.cve_enricher.urllib.request.urlopen")
    def test_fetch_network_error_returns_empty_dict(self, mock_urlopen):
        """EPSS is a nice-to-have — transient failures must NOT break the
        boil. Empty dict lets the caller skip the write and move on."""
        import urllib.error

        from cauldron.ai.cve_enricher import _fetch_epss_batch

        mock_urlopen.side_effect = urllib.error.URLError("connection refused")

        assert _fetch_epss_batch(["CVE-2021-41773"]) == {}

    def test_epss_cache_round_trip(self, tmp_path):
        from cauldron.ai.cve_enricher import EPSSCache

        cache = EPSSCache(cache_file=tmp_path / "epss.json")
        cache.put_batch({"CVE-2021-41773": 0.97, "CVE-2020-1472": 0.94})

        # Reload from disk to exercise the persistence path, not just
        # the in-memory dict.
        cache2 = EPSSCache(cache_file=tmp_path / "epss.json")
        assert cache2.get("CVE-2021-41773") == pytest.approx(0.97)
        assert cache2.get("CVE-2020-1472") == pytest.approx(0.94)
        assert cache2.get("CVE-1234-5678") is None

    def test_epss_cache_respects_ttl(self, tmp_path):
        from cauldron.ai.cve_enricher import EPSSCache

        cache = EPSSCache(cache_file=tmp_path / "epss.json", ttl=1)
        cache.put_batch({"CVE-2021-41773": 0.5})
        assert cache.get("CVE-2021-41773") == pytest.approx(0.5)

        import time as _t
        _t.sleep(1.1)
        assert cache.get("CVE-2021-41773") is None  # expired


@pytest.mark.skipif(not verify_connection(), reason="Neo4j not available")
class TestEnrichEPSSFromGraph:
    """Integration: pulls CVE IDs from the graph, writes v.epss."""

    @pytest.fixture(autouse=True)
    def _clean_db(self):
        clear_database()
        yield
        clear_database()

    @patch("cauldron.ai.cve_enricher.urllib.request.urlopen")
    def test_writes_epss_on_cve_nodes(self, mock_urlopen, tmp_path, monkeypatch):
        """Seed a CVE node without epss, expect v.epss populated."""
        import json as _json
        from unittest.mock import MagicMock as _MagicMock

        from cauldron.ai.cve_enricher import enrich_epss_from_graph

        # Isolate cache to a temp file so prior runs don't pollute.
        monkeypatch.setattr(
            "cauldron.ai.cve_enricher.EPSS_CACHE_FILE",
            tmp_path / "epss.json",
        )

        with get_session() as session:
            session.run("""
                CREATE (v:Vulnerability {cve_id: 'CVE-2021-41773',
                                         source: 'nvd', cvss: 7.5})
            """)

        mock_response = _MagicMock()
        mock_response.read.return_value = _json.dumps({
            "status": "OK",
            "data": [{"cve": "CVE-2021-41773", "epss": "0.97351",
                      "percentile": "0.99985", "date": "2026-04-24"}],
        }).encode()
        mock_urlopen.return_value = mock_response

        stats = enrich_epss_from_graph()

        assert stats["checked"] == 1
        assert stats["fetched"] == 1
        assert stats["updated"] == 1

        with get_session() as session:
            r = session.run(
                "MATCH (v:Vulnerability {cve_id: 'CVE-2021-41773'}) "
                "RETURN v.epss AS epss",
            ).single()
            assert r["epss"] == pytest.approx(0.97351)

    @patch("cauldron.ai.cve_enricher.urllib.request.urlopen")
    def test_skips_cauldron_synthetic_ids(self, mock_urlopen, tmp_path, monkeypatch):
        """CAULDRON-* IDs have no EPSS upstream — must not be queried."""
        from cauldron.ai.cve_enricher import enrich_epss_from_graph

        monkeypatch.setattr(
            "cauldron.ai.cve_enricher.EPSS_CACHE_FILE",
            tmp_path / "epss.json",
        )

        with get_session() as session:
            session.run("""
                CREATE (v:Vulnerability {cve_id: 'CAULDRON-125',
                                         source: 'exploit_db'})
            """)

        stats = enrich_epss_from_graph()

        assert stats["checked"] == 0
        mock_urlopen.assert_not_called()

    @patch("cauldron.ai.cve_enricher.urllib.request.urlopen")
    def test_skips_cves_already_having_epss(self, mock_urlopen, tmp_path, monkeypatch):
        """Incremental re-runs only touch CVEs still missing a score."""
        from cauldron.ai.cve_enricher import enrich_epss_from_graph

        monkeypatch.setattr(
            "cauldron.ai.cve_enricher.EPSS_CACHE_FILE",
            tmp_path / "epss.json",
        )

        with get_session() as session:
            session.run("""
                CREATE (v:Vulnerability {cve_id: 'CVE-2021-41773',
                                         source: 'nvd', epss: 0.42})
            """)

        stats = enrich_epss_from_graph()

        assert stats["checked"] == 0
        mock_urlopen.assert_not_called()


    @patch("cauldron.ai.cve_enricher.settings")
    @patch("cauldron.ai.cve_enricher.urllib.request.urlopen")
    @patch("cauldron.ai.cve_enricher._rate_limit")
    def test_legitimate_empty_result_is_cached(
        self, mock_rate, mock_urlopen, mock_settings, tmp_path,
    ):
        """Contrast case: when NVD authoritatively returns zero CVEs, that
        IS cacheable — we don't want to re-query the same unknown product
        every boil."""
        import json as _json
        from unittest.mock import MagicMock as _MagicMock

        from cauldron.ai.cve_enricher import CVECache, enrich_service

        mock_settings.nvd_api_key = None

        mock_response = _MagicMock()
        mock_response.read.return_value = _json.dumps({"vulnerabilities": []}).encode()
        mock_urlopen.return_value = mock_response

        cache_file = tmp_path / "cache.json"
        cache = CVECache(cache_file=cache_file)

        # Use a product we know will derive a CPE — Apache is in PRODUCT_CPE_MAP
        result = enrich_service("Apache httpd", "2.4.49", cache=cache)

        # Authoritative zero-CVE answer: no error, and cache gained an entry
        assert result.error is None
        assert result.cves == []
        assert cache.size == 1


def urllib_403_error():
    """Create a sequence of 403 errors for testing."""
    import urllib.error
    for _ in range(4):
        yield urllib.error.HTTPError("https://nvd.nist.gov", 403, "Forbidden", {}, None)


class TestUpsertVulnerabilityLinking:
    """Regression guards around the CPE prefix used to link Vulnerability
    nodes to matching Services. The bug this class pins down: the linker
    used to hardcode ``cpe:/a:`` regardless of CPE part type, so every
    OS-typed CPE (ESXi, Cisco IOS, MikroTik RouterOS, PAN-OS, FortiOS)
    silently missed the STARTS-WITH link pass and could only be caught
    by product+version literal equality."""

    def _captured_prefixes(self, cpe_in: str) -> list[str]:
        """Run ``_upsert_vulnerability`` against a MagicMock session and
        collect every ``prefix`` kwarg it would have sent to Cypher."""
        from unittest.mock import MagicMock

        from cauldron.ai.cve_enricher import CVEInfo, _upsert_vulnerability

        session = MagicMock()
        _upsert_vulnerability(
            session,
            product="",
            version="",
            cpe_list=[cpe_in],
            cve=CVEInfo(cve_id="CVE-9999-0001", cvss=7.5),
        )
        prefixes: list[str] = []
        for call in session.run.call_args_list:
            kwargs = call.kwargs
            if "prefix" in kwargs:
                prefixes.append(kwargs["prefix"])
        return prefixes

    def test_os_typed_cpe_links_via_o_prefix(self):
        """ESXi sits on Services as ``cpe:/o:vmware:esxi:7.0.3``; the
        linker must build an ``cpe:/o:`` prefix so STARTS WITH matches."""
        prefixes = self._captured_prefixes("cpe:/o:vmware:esxi:7.0.3")
        assert prefixes == ["cpe:/o:vmware:esxi:7.0.3"]

    def test_application_cpe_still_uses_a_prefix(self):
        """Application CPEs must keep the ``cpe:/a:`` prefix — the fix
        must not flip the default."""
        prefixes = self._captured_prefixes("cpe:/a:apache:http_server:2.4.49")
        assert prefixes == ["cpe:/a:apache:http_server:2.4.49"]

    def test_os_cpe_not_in_allowlist_is_dropped_not_misprefixed(self):
        """``_cpe22_to_23`` only emits OS CPEs for high-value products
        (ESXi, Cisco IOS, etc.). Other o-types return None — so the
        linker must not emit *any* prefix rather than fall back to an
        a-typed guess."""
        prefixes = self._captured_prefixes("cpe:/o:microsoft:windows_10")
        assert prefixes == []
