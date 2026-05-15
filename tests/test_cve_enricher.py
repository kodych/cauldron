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
    _cve_is_av_local,
    _cve_is_dos_only,
    _cve_is_gold,
    _cve_is_local_only,
    _cve_matches_product,
    _cve_priority_key,
    _cve_requires_admin,
    _extract_version,
    _filter_host_os_cves_by_ownership,
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
        """NVD refs carry no Exploit tag AND ExploitIndex has no entry
        → ``has_exploit`` stays False. Mocking the index to empty so
        the test stays deterministic on systems where the local cache
        already covers CVE-2021-42013 from a previous refresh."""
        from unittest.mock import patch
        cve_data = SAMPLE_CVE_RESPONSE["vulnerabilities"][1]["cve"]
        with patch("cauldron.exploits.exploit_index.EXPLOIT_INDEX.references",
                   return_value=[]):
            cve = _parse_cve(cve_data)

        assert cve is not None
        assert cve.cve_id == "CVE-2021-42013"
        assert cve.cvss == 9.8
        assert cve.severity == "CRITICAL"
        assert cve.has_exploit is False
        assert cve.exploit_sources == ""

    def test_parse_cve_exploit_sources_nvd_only(self):
        """When the NVD-reference scan finds an Exploit-tagged ref,
        ``exploit_sources`` is ``"nvd"``."""
        cve_data = SAMPLE_CVE_RESPONSE["vulnerabilities"][0]["cve"]
        cve = _parse_cve(cve_data)
        assert cve is not None
        assert cve.has_exploit is True
        # ExploitIndex may or may not have CVE-2021-41773 cached in dev
        # environments; the only invariant we can pin is that ``nvd`` is
        # present (the NVD-reference scan above set has_exploit).
        assert "nvd" in cve.exploit_sources

    def test_parse_cve_augmented_by_exploit_index(self):
        """NVD-reference scan finds zero Exploit-tagged refs, but the
        ``ExploitIndex`` has a Metasploit module for the CVE — augmentation
        flips ``has_exploit`` to True and records ``exploit_sources`` as
        ``"metasploit"``. Regression for the CVE-2007-2447 Samba usermap
        case where NVD tagged nothing as Exploit yet the canonical
        ``exploit/multi/samba/usermap_script`` module exists."""
        from unittest.mock import patch
        from cauldron.exploits.exploit_index import ExploitRef

        cve_data = {
            "id": "CVE-2007-2447",
            "descriptions": [{"lang": "en", "value": "Samba username map RCE"}],
            "metrics": {
                "cvssMetricV2": [{
                    "cvssData": {"baseScore": 6.0, "vectorString": "AV:N/AC:M/Au:S/C:P/I:P/A:P"},
                    "baseSeverity": "MEDIUM",
                }]
            },
            "references": [
                {"url": "http://example.com/advisory", "tags": ["Vendor Advisory"]},
            ],
        }
        # ExploitIndex has the Metasploit module — augmentation should
        # promote has_exploit from False to True.
        mock_ref = ExploitRef(
            source="metasploit",
            ref_id="exploit/multi/samba/usermap_script",
            url="https://www.rapid7.com/db/modules/exploit/multi/samba/usermap_script",
            title="Samba usermap script RCE",
        )
        with patch("cauldron.exploits.exploit_index.EXPLOIT_INDEX.references",
                   return_value=[mock_ref]):
            cve = _parse_cve(cve_data)
        assert cve is not None
        assert cve.has_exploit is True  # promoted by augmentation
        assert cve.exploit_sources == "metasploit"
        assert cve.exploit_url == mock_ref.url  # surfaced for UI deep-link

    def test_parse_cve_augmentation_never_demotes(self):
        """NVD already found an Exploit-tagged ref → ``has_exploit=True``.
        ExploitIndex must not flip it back to False even if the index
        has no entry for this CVE (augmentation is one-directional)."""
        from unittest.mock import patch
        cve_data = SAMPLE_CVE_RESPONSE["vulnerabilities"][0]["cve"]
        with patch("cauldron.exploits.exploit_index.EXPLOIT_INDEX.references",
                   return_value=[]):
            cve = _parse_cve(cve_data)
        assert cve is not None
        assert cve.has_exploit is True
        assert "nvd" in cve.exploit_sources

    def test_parse_cve_multi_source_combines(self):
        """NVD Exploit-ref + ExploitDB + Metasploit all present →
        ``exploit_sources`` records all three in canonical order."""
        from unittest.mock import patch
        from cauldron.exploits.exploit_index import ExploitRef

        cve_data = SAMPLE_CVE_RESPONSE["vulnerabilities"][0]["cve"]  # has nvd tag
        with patch("cauldron.exploits.exploit_index.EXPLOIT_INDEX.references",
                   return_value=[
                       ExploitRef("exploitdb", "EDB-50406",
                                  "https://www.exploit-db.com/exploits/50406", "Apache"),
                       ExploitRef("metasploit", "exploit/multi/http/apache_path",
                                  "https://r/m", "Apache path traversal"),
                   ]):
            cve = _parse_cve(cve_data)
        assert cve is not None
        # Canonical order: nvd → exploitdb → metasploit
        assert cve.exploit_sources == "nvd+exploitdb+metasploit"

    def test_parse_cve_index_failure_does_not_crash(self):
        """If ``ExploitIndex.references`` raises (corrupt cache, import
        failure, anything) ``_parse_cve`` falls back to the NVD-only
        signal and never propagates the error — augmentation is best-effort,
        never fatal."""
        from unittest.mock import patch
        cve_data = SAMPLE_CVE_RESPONSE["vulnerabilities"][0]["cve"]
        with patch("cauldron.exploits.exploit_index.EXPLOIT_INDEX.references",
                   side_effect=RuntimeError("cache corrupt")):
            cve = _parse_cve(cve_data)
        assert cve is not None
        assert cve.has_exploit is True  # NVD tag survives
        assert cve.exploit_sources == "nvd"

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

    def test_parse_cve_v40_primary(self):
        """NVD tags new CVEs (post-2023) with CVSS 4.0. Without v40 in
        the preference chain, modern findings came back cvss=None and
        the UI showed "N/A" — a regression that hit every fresh vuln
        the moment NVD migrated its scoring methodology."""
        cve_data = {
            "id": "CVE-2024-9999",
            "descriptions": [{"lang": "en", "value": "Hypothetical v4-only CVE"}],
            "metrics": {
                "cvssMetricV40": [
                    {
                        "cvssData": {
                            "version": "4.0",
                            "baseScore": 8.7,
                            "vectorString": (
                                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/"
                                "VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                            ),
                            "baseSeverity": "HIGH",
                        },
                    },
                ],
            },
            "references": [],
        }
        cve = _parse_cve(cve_data)
        assert cve is not None
        assert cve.cvss == 8.7
        assert cve.severity == "HIGH"
        assert cve.cvss_vector and cve.cvss_vector.startswith("CVSS:4.0/")

    def test_parse_cve_prefers_v40_over_v31_when_both_present(self):
        """NVD sometimes backports both v31 and v40 onto the same CVE.
        The v40 score reflects the current (post-2023) methodology and
        must win — pin that so a future re-ordering of the preference
        chain can't silently regress the source-of-truth choice."""
        cve_data = {
            "id": "CVE-2024-8888",
            "descriptions": [{"lang": "en", "value": "Dual-scored CVE"}],
            "metrics": {
                "cvssMetricV40": [
                    {
                        "cvssData": {
                            "version": "4.0",
                            "baseScore": 7.3,
                            "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
                            "baseSeverity": "HIGH",
                        },
                    },
                ],
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 9.8,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseSeverity": "CRITICAL",
                        },
                    },
                ],
            },
            "references": [],
        }
        cve = _parse_cve(cve_data)
        assert cve is not None
        assert cve.cvss == 7.3
        assert cve.severity == "HIGH"
        assert cve.cvss_vector and cve.cvss_vector.startswith("CVSS:4.0/")

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

    def test_cpe22_os_linux_kernel_with_major_minor(self):
        """Linux kernel CPE from nmap's ``<osclass>`` lands with a
        major.minor version slot (``cpe:/o:linux:linux_kernel:2.6``).
        Must convert so the host-OS enricher can query NVD for the
        kernel privesc backlog — without it CVE-2009-2698 and the
        rest of the AV:L Linux kernel CVEs never surface."""
        result = _cpe22_to_23("cpe:/o:linux:linux_kernel:2.6")
        assert result == "cpe:2.3:o:linux:linux_kernel:2.6:*:*:*:*:*:*:*"

    def test_cpe22_os_linux_kernel_no_version_returns_none(self):
        """Versionless ``cpe:/o:linux:linux_kernel`` would flood — NVD
        has thousands of kernel CVEs and we have no way to filter by
        applicable major.minor without a concrete version. Drop."""
        result = _cpe22_to_23("cpe:/o:linux:linux_kernel")
        assert result is None

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

    def test_metasploitable_samba_usermap_case(self):
        """The Metasploitable critique case (CVE-2007-2447):

        nmap on Samba :445 emits ``<service product="Samba smbd"
        version="3.0.20-Debian">`` AND a versionless ``<cpe>cpe:/a:samba:
        samba</cpe>``. Cauldron must MERGE the service version into the
        CPE so NVD queries can hit version-pinned CVEs like the
        ``samba:samba:3.0.0`` ... ``:3.0.20`` set behind CVE-2007-2447.
        Before this fix the versionless CPE drove a versionless NVD
        query and the strict applicability rule from P1 dropped the
        finding.
        """
        cpe_list = ["cpe:/a:samba:samba"]
        result = _get_cpe_for_service(cpe_list, "Samba smbd", "3.0.20-Debian")
        assert result == "cpe:2.3:a:samba:samba:3.0.20:*:*:*:*:*:*:*"

    def test_versionless_service_does_not_force_version(self):
        """Samba :139 reports ``version='3.X - 4.X'`` — a real range, not
        a missing pin. ``_extract_version`` returns ``"*"`` for this and
        we must NOT inject ``"3.X"`` into the CPE. The CPE stays
        versionless so the strict-applicability rule treats it as
        legitimately unknown.
        """
        cpe_list = ["cpe:/a:samba:samba"]
        result = _get_cpe_for_service(cpe_list, "Samba smbd", "3.X - 4.X")
        assert result == "cpe:2.3:a:samba:samba:*:*:*:*:*:*:*:*"

    def test_explicit_nmap_cpe_version_not_overridden(self):
        """When nmap supplies a pinned version in the CPE itself, the
        service-version-attr merge must NOT override it. Trust nmap's
        explicit choice over heuristic merging.
        """
        cpe_list = ["cpe:/a:apache:http_server:2.4.49"]
        # Even if service.version disagrees, the CPE pin wins.
        result = _get_cpe_for_service(cpe_list, "Apache httpd", "2.4.51")
        assert result == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"

    def test_no_version_attribute_no_upgrade(self):
        """Service version=None + versionless nmap CPE → stays versionless."""
        cpe_list = ["cpe:/a:unrealircd:unrealircd"]
        result = _get_cpe_for_service(cpe_list, "UnrealIRCd", None)
        assert result == "cpe:2.3:a:unrealircd:unrealircd:*:*:*:*:*:*:*:*"


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
    """Actionable-gold filter — single strict rule: keep only CVEs with an
    actionable-exploit signal (NVD ``has_exploit`` tag OR CISA-KEV listing,
    both meaning real exploit code exists). Version applicability is
    enforced upstream by ``_cve_applies_to``; when no version is known, we
    assume the service runs the latest release and keep the CVEs an
    operator could actually run against it. KEV counts as exploit signal
    but does NOT bypass the other gates — hard rejects (local/physical
    vector, pure DoS, admin-required) and the versionless recency cut
    apply equally to KEV and to has_exploit-tagged CVEs.
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

    # --- CISA KEV as exploit signal ---

    def test_kev_counts_as_exploit_signal(self):
        """KEV-listed CVE clears the actionable-exploit gate even without
        an NVD ``Exploit``-tagged reference. CISA itself confirms in-the-wild
        exploitation — that carries the same "real exploit code exists"
        weight as a tagged reference."""
        cve = self._cve(cvss=4.5, has_exploit=False, in_cisa_kev=True)
        assert _cve_is_gold(cve) is True

    def test_kev_does_not_override_local(self):
        """KEV doesn't help on a network scan if vector is local-only —
        the hard reject fires before the exploit-signal gate."""
        cve = self._cve(cvss=9.8, has_exploit=True, in_cisa_kev=True,
                        vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert _cve_is_gold(cve) is False

    def test_kev_does_not_override_dos_only(self):
        """CVE-2023-44487 (HTTP/2 Rapid Reset) — KEV but pure DoS.
        Attack-in-the-wild yes, pentest gold on a netscan no."""
        cve = self._cve(cvss=7.5, has_exploit=True, in_cisa_kev=True,
                        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
        assert _cve_is_gold(cve) is False

    def test_kev_does_not_override_admin_required(self):
        """KEV is no longer a blanket override. A PR:H CVE — admin shell
        is already required to exploit — drops even when flagged KEV.
        Post-exploitation CVEs are not a way in regardless of in-the-wild
        attack frequency."""
        cve = self._cve(cvss=9.8, has_exploit=True, in_cisa_kev=True,
                        vector="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")
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

    def test_versionless_kev_subject_to_recency_cut(self):
        """KEV is no longer a free pass through the versionless recency
        cut. An ancient KEV-flagged CVE on a "we don't know the version"
        service drops with the same logic as any other ancient CVE —
        the recency cut exists because we have to assume the service
        runs a current release, and NVD CPE attribution bugs (CVE
        attached to a wildcard CPE despite being a much newer feature)
        produce reverse-temporal noise that KEV used to mask."""
        ancient_kev = self._cve_with_year(
            2017, has_exploit=True, in_cisa_kev=True)
        assert _cve_is_gold(ancient_kev, versionless=True) is False

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

    def test_versionless_os_cpe_skips_recency_cut(self):
        """OS-typed CPE queries (``cpe:2.3:o:microsoft:windows_7:*:…``)
        are versionless by shape — the major OS version is encoded in
        the product name, not the version slot. Applying the 5-year
        "assume latest" recency cut to them drops every Win 7 / 2008 /
        XP CVE that isn't in CISA KEV, even on a legacy host the
        operator is staring at and that clearly can't be patched.

        Regression for the THM Blue sanity-check finding where the
        pipeline returned only three NVD CVEs (CVE-2017-0144,
        CVE-2018-8373, CVE-2012-4969) for a Win 7 SP1 box — every
        other Win 7 CVE older than 2021 was cut here. The MS17-010
        family CVEs (CVE-2017-0143/45/46/47/48) all have public
        exploits but aren't individually KEV-listed, so the recency
        cut dropped them silently."""
        # 2017 Win 7 CVE with a public exploit, not in KEV — would
        # normally be dropped by the versionless recency cut. With
        # ``os_cpe=True`` it must pass.
        ms17_family = self._cve_with_year(2017, has_exploit=True, in_cisa_kev=False)
        assert _cve_is_gold(ms17_family, versionless=True, os_cpe=True) is True
        # Without the carve-out the same CVE drops — sanity-check the
        # control path.
        assert _cve_is_gold(ms17_family, versionless=True, os_cpe=False) is False

    def test_os_cpe_carve_out_still_requires_actionable_exploit(self):
        """The OS-CPE carve-out only lifts the recency cut — it does
        not bypass the exploit-signal gate. A theoretical 2014 RCE
        with no public PoC and no KEV listing stays out of the "gold"
        set even on a Win 7 host, otherwise the pipeline would flood
        every Windows scan with hundreds of CVSS-9.x entries that
        nobody has tooling for. KEV-flagged ancient CVEs pass because
        KEV satisfies the exploit-signal gate AND ``os_cpe`` lifts
        the recency cut for legacy OS families."""
        theoretical = self._cve_with_year(2014, has_exploit=False, in_cisa_kev=False)
        assert _cve_is_gold(theoretical, versionless=True, os_cpe=True) is False
        kev_ancient = self._cve_with_year(2010, has_exploit=False, in_cisa_kev=True)
        assert _cve_is_gold(kev_ancient, versionless=True, os_cpe=True) is True

    # --- Host-OS context: AV:L kernel privesc survives the gate ---

    def test_host_os_keeps_av_local_cves(self):
        """Service-level queries drop AV:L (local attack vector) CVEs
        — for an external-surface scan local privesc isn't reachable
        from the network. Host-OS queries invert that: the enricher
        only runs against the Host node when the operator presumes
        foothold context, and AV:L kernel privesc (CVE-2009-2698,
        CVE-2010-3904, …) is exactly the gold the host-OS pipeline
        exists to surface. ``host_os=True`` must keep these."""
        kernel_privesc = CVEInfo(
            cve_id="CVE-2009-2698",
            cvss=7.2,
            cvss_vector="AV:L/AC:L/Au:N/C:C/I:C/A:C",
            has_exploit=True,
            in_cisa_kev=False,
            published="2009-09-15",
        )
        # Service-level: dropped — operator can't reach AV:L from outside.
        assert _cve_is_gold(kernel_privesc, host_os=False) is False
        # Host-OS: kept — post-foothold escalation gold.
        assert _cve_is_gold(kernel_privesc, host_os=True, os_cpe=True) is True

    def test_host_os_still_drops_av_physical(self):
        """The host-OS carve-out lifts AV:L only. AV:P (physical
        access) stays out of scope on every network engagement that
        doesn't involve a hardware lab — that lift would do nothing
        useful and would flood the result set with TPM / BadUSB-class
        bugs the operator can't reach."""
        physical = CVEInfo(
            cve_id="CVE-X-PHYS",
            cvss=8.5,
            cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            has_exploit=True,
            published="2024-01-01",
        )
        assert _cve_is_gold(physical, host_os=True, os_cpe=True) is False

    def test_host_os_keeps_dos_drop(self):
        """Pure-DoS CVEs are useless for red-team gold hunting in both
        service-level and host-OS contexts — operator wants foothold
        and lateral movement, not crashing the box. The DoS gate
        must still fire even when ``host_os=True``."""
        dos = CVEInfo(
            cve_id="CVE-X-DOS",
            cvss=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            has_exploit=True,
            published="2023-01-01",
        )
        assert _cve_is_gold(dos, host_os=True, os_cpe=True) is False

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


class TestFilterHostOSCVEsByOwnership:
    """Per-CVE AV:L gate at host-OS upsert time.

    The cache (``CVECache`` keyed by CPE) carries the full AV:L + AV:N
    result for every OS CPE the pipeline has queried. This filter is
    the per-host upsert decision: AV:L kernel-privesc CVEs only flow
    through to ``(:Host)-[:HAS_VULN]->(:Vulnerability)`` when the host
    is already marked owned. Pre-foothold AV:L is dead weight competing
    with AV:N attack-surface findings; Mark-as-Owned is the event that
    flips them into actionability (v0.2.0 piece B re-runs this filter).
    """

    AV_N_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    AV_L_VECTOR = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def _cve(self, cve_id: str, vector: str) -> CVEInfo:
        return CVEInfo(
            cve_id=cve_id, cvss=7.5, cvss_vector=vector, has_exploit=True,
        )

    def test_av_local_detected(self):
        assert _cve_is_av_local(self._cve("X", self.AV_L_VECTOR)) is True
        assert _cve_is_av_local(self._cve("X", self.AV_N_VECTOR)) is False

    def test_av_local_missing_vector_returns_false(self):
        """Defensive — no vector string means we can't conclude AV:L,
        so we don't apply the ownership gate and let the CVE through."""
        no_vector = CVEInfo(cve_id="X", cvss=7.5, cvss_vector=None,
                            has_exploit=True)
        assert _cve_is_av_local(no_vector) is False

    def test_owned_host_keeps_everything(self):
        """When the operator has shell on the box, every CVE the gold
        filter accepted at NVD-query time stays — AV:L kernel privesc
        becomes the exact gold the host-OS pipeline exists to surface."""
        cves = [
            self._cve("CVE-N-1", self.AV_N_VECTOR),
            self._cve("CVE-L-1", self.AV_L_VECTOR),
            self._cve("CVE-L-2", self.AV_L_VECTOR),
        ]
        kept, skipped = _filter_host_os_cves_by_ownership(cves, host_is_owned=True)
        assert [c.cve_id for c in kept] == ["CVE-N-1", "CVE-L-1", "CVE-L-2"]
        assert skipped == 0

    def test_unowned_host_drops_av_local(self):
        """Pre-foothold the AV:L entries are noise — operator can't run
        a local privesc against a box they don't have shell on. AV:N
        external attack surface stays."""
        cves = [
            self._cve("CVE-N-1", self.AV_N_VECTOR),
            self._cve("CVE-L-1", self.AV_L_VECTOR),
            self._cve("CVE-L-2", self.AV_L_VECTOR),
        ]
        kept, skipped = _filter_host_os_cves_by_ownership(cves, host_is_owned=False)
        assert [c.cve_id for c in kept] == ["CVE-N-1"]
        assert skipped == 2

    def test_empty_input(self):
        kept, skipped = _filter_host_os_cves_by_ownership([], host_is_owned=False)
        assert kept == []
        assert skipped == 0

    def test_unowned_all_av_local_returns_empty(self):
        """A host whose entire CVE list is kernel-privesc (Linux 2.6
        with only AV:L kernel CVEs surviving the gold filter) produces
        an empty upsert list pre-foothold, but the cache still holds
        the full result for the eventual Mark-as-Owned re-enrichment."""
        cves = [
            self._cve("CVE-L-1", self.AV_L_VECTOR),
            self._cve("CVE-L-2", self.AV_L_VECTOR),
        ]
        kept, skipped = _filter_host_os_cves_by_ownership(cves, host_is_owned=False)
        assert kept == []
        assert skipped == 2


class TestReenrichHostOSOnOwnership:
    """Mark-as-Owned trigger — re-enriches a single host's host-OS CVE
    edges from cache when ownership flips. Reads from ``CVECache`` only,
    never re-queries NVD, deletes AV:L edges on un-own. Tests cover the
    early-exit paths (missing host, no os_cpe, cold cache) and the
    return-stats contract — the integration paths against a populated
    Neo4j live elsewhere.
    """

    def test_host_missing_returns_gracefully(self):
        """The PATCH endpoint already validated the host exists before
        scheduling this BackgroundTask, but a concurrent reset/wipe
        could remove the host between PATCH commit and task start.
        Function must return cleanly with ``host_missing=true``, not
        raise — re-enrichment failure cannot break the ownership flip."""
        from cauldron.ai.cve_enricher import reenrich_host_os_on_ownership

        # No setup — bogus IP guaranteed to miss
        stats = reenrich_host_os_on_ownership("203.0.113.255", owned=True)
        assert stats["host_missing"] is True
        assert stats["av_l_added"] == 0
        assert stats["av_l_removed"] == 0

    def test_host_missing_unowned_path(self):
        """Symmetric path for owned=False — still no exception, same
        graceful return shape."""
        from cauldron.ai.cve_enricher import reenrich_host_os_on_ownership

        stats = reenrich_host_os_on_ownership("203.0.113.255", owned=False)
        assert stats["host_missing"] is True

    def test_stats_shape_contract(self):
        """The BackgroundTask runner needs a stable return shape so
        future logging / metrics can read fields without defensive
        gets. Lock the key set."""
        from cauldron.ai.cve_enricher import reenrich_host_os_on_ownership

        stats = reenrich_host_os_on_ownership("203.0.113.255", owned=True)
        expected_keys = {
            "ip", "owned", "av_l_added", "av_l_removed",
            "cache_miss", "no_os_cpe", "host_missing",
        }
        assert set(stats.keys()) == expected_keys

    def test_never_raises_on_unexpected_failure(self, monkeypatch):
        """BackgroundTask contract: exceptions inside the task must not
        bubble out. The ownership PATCH already committed server-side
        — only logging is the channel for re-enrichment errors."""
        from cauldron.ai import cve_enricher
        from cauldron.graph import connection

        def boom(*_a, **_kw):
            raise RuntimeError("simulated Neo4j outage")

        # ``reenrich_host_os_on_ownership`` does an in-function import
        # of ``get_session``, so patch the source module to make every
        # lookup land on the failing stub.
        monkeypatch.setattr(connection, "get_session", boom)
        # Must not raise — function catches and logs
        stats = cve_enricher.reenrich_host_os_on_ownership("10.0.0.1", owned=True)
        # No fields were populated because the exception fired early,
        # but the dict must still come back well-formed.
        assert stats["ip"] == "10.0.0.1"
        assert stats["owned"] is True


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

    def test_versionless_drops_range_bounded_cve(self):
        """Versionless service: range-bounded CVEs are dropped because we
        cannot prove the unknown version falls inside the range.

        Policy reversal: the previous rule kept range-bounded CVEs on
        versionless services because the operator might be running a
        modern vendor product where nmap missed the version. That rule
        produced unacceptable noise on legacy gear (Kioptrix-class boxes
        where Samba 2.2.x without a detected version got attached to
        every modern Samba 3.5+/4.x CVE).

        Recovery path for the rarer modern-product-no-version case: the
        operator re-runs nmap with stronger version detection
        (``--script smb-version,smb-os-discovery`` / ``-sV
        --version-intensity 9``) so the service gets a real version,
        then re-enriches. With a real version the versioned branch
        handles range comparison correctly. The wildcard-retry path
        inside ``_query_nvd_cpe`` already threads the original service
        version through ``service_version_override``, so CrushFTP /
        ESXi-style vendor CVEs on services where nmap reported a patch
        level that NVD didn't pin (the original reason for the looser
        rule) still flow through the versioned branch — only services
        with no version at all are affected.
        """
        assert _cve_applies_to(self.RANGED_CVE, "http_server", None) is False

    def test_versionless_keeps_unconstrained_cve(self):
        """CVE with wildcard CPE applies to any version — keep."""
        assert _cve_applies_to(self.UNCONSTRAINED_CVE, "http_server", None) is True

    def test_no_config_passes_through(self):
        """CVEs without CPE configurations aren't filtered here."""
        assert _cve_applies_to(self.NO_CONFIG_CVE, "http_server", None) is True

    # --- OS-typed CPE carve-out ---
    #
    # NVD's older OS records (the 2017-and-earlier Windows backlog,
    # including CVE-2017-0144 EternalBlue) put the SP / edition in the
    # update / edition slots and leave the version slot as ``-`` ("NA"
    # baseline marker, not a missing entry). The generic
    # application-CPE rule reads parts[5]="-" as constrained, so without
    # the OS-CPE carve-out MS17-010 silently disappears from results
    # for the very Win 7 SP1 hosts where it's most relevant.

    # CVE-2017-0144 / MS17-010 — every cpeMatch carries ``-`` in the
    # version slot with the actual SP in the update slot. Reproduces
    # the exact shape NVD ships for EternalBlue.
    ETERNALBLUE_CVE = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [
                    {"criteria": "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:x64:*"},
                    {"criteria": "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:x86:*"},
                ],
            }],
        }],
    }

    def test_versionless_os_cpe_keeps_dash_version_slot(self):
        """``os_cpe=True`` skips the version-slot check entirely. The
        product name (``windows_7``) carries the OS identity; the ``-``
        in NVD's version slot is the RTM baseline marker, not a missing
        entry. Without this carve-out CVE-2017-0144 silently drops on
        every Win 7 scan."""
        assert _cve_applies_to(
            self.ETERNALBLUE_CVE, "windows_7", None, os_cpe=True,
        ) is True

    def test_versionless_application_still_drops_dash_version_slot(self):
        """The carve-out is OS-only — application-typed queries still
        treat ``-`` in the version slot as constrained, so the existing
        protection against ancient ``apache:http_server:-`` style
        entries is unaffected."""
        ancient_app = {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [
                        {"criteria": "cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*"},
                    ],
                }],
            }],
        }
        assert _cve_applies_to(ancient_app, "http_server", None) is False
        # Default ``os_cpe=False`` matches the explicit form.
        assert _cve_applies_to(
            ancient_app, "http_server", None, os_cpe=False,
        ) is False

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
        """A version string nmap couldn't parse behaves like "no version".
        Under the strict policy: range-bounded CVEs drop (we cannot
        verify), unconstrained CVEs pass (apply regardless of version).
        """
        assert _cve_applies_to(self.RANGED_CVE, "http_server", "unknown-build-xyz") is False
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

    def test_range_bounded_cve_dropped_for_unknown_version(self):
        """The previous policy kept range-bounded CVEs on versionless
        services to catch modern-vendor CVEs like CVE-2024-4040
        (CrushFTP, range 10.0.0-10.7.1) even when nmap missed the
        version. New policy reverses that: we cannot prove an unknown
        version falls inside the range, and the same loose rule was
        producing massive noise on legacy gear (Samba 2.2.x getting
        every modern Samba 3.5+/4.x CVE attached).

        Operator recovery path for the modern-vendor case: rescan with
        stronger version detection (``-sV --version-intensity 9``,
        product-specific NSE scripts) so the service ends up versioned
        and the range comparison can actually run.
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
        # Versionless: dropped, we cannot prove applicability.
        assert _cve_applies_to(crushftp_ranged_cve, "crushftp", None) is False
        # With a version inside the range -- kept.
        assert _cve_applies_to(crushftp_ranged_cve, "crushftp", "10.3.0") is True
        # With a version outside the range -- dropped.
        assert _cve_applies_to(crushftp_ranged_cve, "crushftp", "10.7.1") is False

    def test_kioptrix_samba_modern_cve_dropped_when_versionless(self):
        """Regression test for the operator's Kioptrix critique: Samba
        smbd is detected (product known) but nmap could not extract a
        version on this old SMB1-only stack. A modern Samba CVE with
        range 3.5.0-4.6.4 (CVE-2017-7494 shape) must drop on a
        versionless service, because the host could equally be Samba
        2.2.x (out of range) or modern Samba (in range), and the modern
        case is recoverable by rescanning with ``--script smb-version``.
        """
        samba_modern_cve = {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "criteria": "cpe:2.3:a:samba:samba:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "3.5.0",
                        "versionEndExcluding": "4.6.4",
                    }]
                }]
            }]
        }
        assert _cve_applies_to(samba_modern_cve, "samba", None) is False
        # Versioned with a Samba 2.2.x — out of range, dropped.
        assert _cve_applies_to(samba_modern_cve, "samba", "2.2.1a") is False
        # Versioned with a Samba 4.0 — in range, kept.
        assert _cve_applies_to(samba_modern_cve, "samba", "4.0.0") is True

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

        from cauldron.ai.cve_enricher import (
            _NVD_RETRY_BUDGET,
            NvdTransientError,
            _execute_nvd_query,
        )

        mock_settings.nvd_api_key = None
        mock_urlopen.side_effect = urllib_403_error()

        with pytest.raises(NvdTransientError):
            _execute_nvd_query("https://example.com", "test")
        assert mock_sleep.call_count == _NVD_RETRY_BUDGET

    @patch("cauldron.ai.cve_enricher.settings")
    @patch("cauldron.ai.cve_enricher.urllib.request.urlopen")
    @patch("cauldron.ai.cve_enricher._rate_limit")
    @patch("cauldron.ai.cve_enricher.time.sleep")
    def test_transient_network_error_raises(self, mock_sleep, mock_rate, mock_urlopen, mock_settings):
        """URLError / OSError / JSONDecodeError after retries raises."""
        import urllib.error

        import pytest

        from cauldron.ai.cve_enricher import (
            _NVD_RETRY_BUDGET,
            NvdTransientError,
            _execute_nvd_query,
        )

        mock_settings.nvd_api_key = None
        mock_urlopen.side_effect = urllib.error.URLError("Connection timed out")

        with pytest.raises(NvdTransientError):
            _execute_nvd_query("https://example.com", "test")
        assert mock_sleep.call_count == _NVD_RETRY_BUDGET

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
        """``_cpe22_to_23`` only emits OS CPEs for products that are
        explicitly registered as ``o:`` in NVD (appliance OSes plus
        the Microsoft Windows family). For everything else it returns
        ``None`` — and the linker must emit *no* prefix rather than
        fall back to an a-typed guess. Linux kernel is a representative
        OS that NVD records but Cauldron deliberately doesn't query
        directly (linux_kernel CVEs flood and the kernel version is
        rarely exposed by remote probes anyway)."""
        prefixes = self._captured_prefixes("cpe:/o:linux:linux_kernel")
        assert prefixes == []

    def test_windows_family_os_cpe_emits_o_prefix(self):
        """Microsoft Windows family CPEs are OS-typed and the product
        name (windows_7, windows_10, …) carries the major-version
        identity — the prefix must keep the ``cpe:/o:`` part type so
        the HAS_VULN linking Cypher reaches Service nodes whose
        ``cpe`` property carries the same OS-typed URI."""
        prefixes = self._captured_prefixes("cpe:/o:microsoft:windows_7::sp1:professional")
        # Empty version slot in the 2.2 URI lands as a versionless prefix
        # ("cpe:/o:microsoft:windows_7") rather than the version-pinned
        # variant — exactly the surface a Service node receives.
        assert prefixes == ["cpe:/o:microsoft:windows_7"]


class TestVulnMergeClauseMultiSource:
    """``_VULN_MERGE_CLAUSE`` must extend ``v.source`` rather than only
    setting it on initial node creation. CVE-2017-0144 was the canary:
    the local exploit_db matcher (CAULDRON-010) ran first, created the
    Vulnerability node with ``v.source = 'exploit_db'``, and the NVD
    enricher's ``ON MATCH`` block then updated cvss / epss / kev but
    left ``source`` untouched — so the UI rendered MS17-010 as a
    DB-only finding even though NVD had verified the same CVE in the
    same boil run.

    This is a Cypher-shape check rather than a live-DB integration
    test so it runs on every CI tier (the orphan-prevention class
    further down covers the end-to-end path on workstations that have
    Neo4j available)."""

    def test_on_match_extends_source(self):
        from cauldron.ai.cve_enricher import _VULN_MERGE_CLAUSE
        on_create, on_match = _VULN_MERGE_CLAUSE.split("ON MATCH")
        # ON CREATE sets nvd as the canonical source for a fresh node.
        assert "v.source = 'nvd'" in on_create
        # ON MATCH appends nvd to whatever the existing writer recorded,
        # idempotent when nvd was already present.
        assert "v.source = CASE" in on_match
        assert "v.source CONTAINS 'nvd'" in on_match
        assert "v.source + '+nvd'" in on_match
        # Existing-but-not-nvd path: a node previously tagged exploit_db
        # turns into 'exploit_db+nvd', not silently kept as 'exploit_db'.
        assert "WHEN v.source IS NULL THEN 'nvd'" in on_match

    def test_on_match_backfills_missing_nvd_fields(self):
        """When the local matcher created the node it didn't know the
        CVSS vector / EPSS / exploit URL — NVD's ON MATCH must fill
        these in via COALESCE, otherwise CVE-2017-0144 stays without
        ``cvss_vector`` and the UI can't render the attack-vector
        chip."""
        from cauldron.ai.cve_enricher import _VULN_MERGE_CLAUSE
        on_match = _VULN_MERGE_CLAUSE.split("ON MATCH")[1]
        assert "v.cvss_vector = COALESCE($cvss_vector, v.cvss_vector)" in on_match
        assert "v.epss = COALESCE($epss, v.epss)" in on_match
        assert "v.exploit_url = COALESCE($exploit_url, v.exploit_url)" in on_match


@pytest.mark.skipif(not verify_connection(), reason="Neo4j not available")
class TestUpsertVulnerabilityOrphanPrevention:
    """The Vulnerability MERGE must never fire when nothing in the
    graph will end up linked to it. An orphan node — Vulnerability
    with zero incoming HAS_VULN edges — silently drifts the
    "Vulnerabilities" count in /api/v1/stats vs `MATCH (v) RETURN
    count(v)`, breaks paths analysis assumptions, and accumulates
    across boil --nvd runs.

    Two layers of defence:

      a) Source: _upsert_vulnerability gates the Vulnerability MERGE
         behind a Service MATCH. If the link target doesn't exist,
         the MERGE clause never executes.
      b) Defensive: enrich_services_from_graph sweeps any remaining
         orphans at the end of every pass (covers legacy data and
         any future code path that resurrects the old pattern).
    """

    @pytest.fixture(autouse=True)
    def _clean_db(self):
        clear_database()
        yield
        clear_database()

    def test_target_endpoint_missing_no_orphan_node(self):
        """target_endpoints contains a service IP that isn't in the
        graph — Vulnerability node must NOT be created."""
        from cauldron.ai.cve_enricher import CVEInfo, _upsert_vulnerability

        with get_session() as session:
            _upsert_vulnerability(
                session,
                product="Apache httpd",
                version="2.4.49",
                cpe_list=[],
                cve=CVEInfo(cve_id="CVE-2021-41773", cvss=9.8),
                target_endpoints=[("10.99.99.99", 80, "tcp")],  # not in graph
            )
            count = session.run(
                "MATCH (v:Vulnerability {cve_id: 'CVE-2021-41773'}) "
                "RETURN count(v) AS c"
            ).single()["c"]
            assert count == 0

    def test_target_endpoint_exists_node_and_edge_created(self):
        """The positive case: when the target Service exists, both the
        Vulnerability node and the HAS_VULN edge appear together."""
        from cauldron.ai.cve_enricher import CVEInfo, _upsert_vulnerability

        with get_session() as session:
            session.run("""
                CREATE (h:Host {ip: '10.0.0.1', state: 'up'})
                CREATE (s:Service {host_ip: '10.0.0.1', port: 80, protocol: 'tcp',
                                   product: 'Apache httpd', version: '2.4.49'})
                CREATE (h)-[:HAS_SERVICE]->(s)
            """)
            _upsert_vulnerability(
                session,
                product="Apache httpd",
                version="2.4.49",
                cpe_list=[],
                cve=CVEInfo(cve_id="CVE-2021-41773", cvss=9.8),
                target_endpoints=[("10.0.0.1", 80, "tcp")],
            )
            row = session.run("""
                MATCH (s:Service {host_ip: '10.0.0.1', port: 80})-[:HAS_VULN]->(v:Vulnerability {cve_id: 'CVE-2021-41773'})
                RETURN v.cvss AS cvss
            """).single()
            assert row is not None
            assert row["cvss"] == 9.8

    def test_legacy_product_version_no_match_no_orphan(self):
        """Legacy fallback path: product+version don't match any service.
        Vulnerability node must NOT be created. The
        ``WITH collect(s) AS svcs WHERE size(svcs) > 0`` guard inside
        the Cypher is what stops the MERGE."""
        from cauldron.ai.cve_enricher import CVEInfo, _upsert_vulnerability

        with get_session() as session:
            session.run("""
                CREATE (h:Host {ip: '10.0.0.1', state: 'up'})
                CREATE (s:Service {host_ip: '10.0.0.1', port: 80, protocol: 'tcp',
                                   product: 'nginx', version: '1.18.0'})
                CREATE (h)-[:HAS_SERVICE]->(s)
            """)
            _upsert_vulnerability(
                session,
                product="Apache httpd",  # no such service
                version="2.4.49",
                cpe_list=[],
                cve=CVEInfo(cve_id="CVE-2021-41773", cvss=9.8),
            )
            count = session.run(
                "MATCH (v:Vulnerability) RETURN count(v) AS c"
            ).single()["c"]
            assert count == 0

    def test_orphan_sweep_removes_pre_existing_dangling_vulns(self):
        """Defensive layer: legacy data (or any future regression) that
        leaves a :Vulnerability without HAS_VULN edges is removed by
        the sweep at the end of enrich_services_from_graph."""
        from cauldron.ai.cve_enricher import enrich_services_from_graph
        from unittest.mock import patch

        with get_session() as session:
            # Seed an orphan plus a properly-linked vuln. The sweep
            # must touch only the orphan.
            session.run("""
                CREATE (v_orphan:Vulnerability {cve_id: 'CVE-9999-ORPHAN', cvss: 5.0, source: 'nvd'})
                CREATE (h:Host {ip: '10.0.0.1', state: 'up'})
                CREATE (s:Service {host_ip: '10.0.0.1', port: 80, protocol: 'tcp',
                                   product: 'nginx', version: '1.18.0'})
                CREATE (h)-[:HAS_SERVICE]->(s)
                CREATE (v_linked:Vulnerability {cve_id: 'CVE-9999-LINKED', cvss: 6.0, source: 'nvd'})
                CREATE (s)-[:HAS_VULN]->(v_linked)
            """)

        # Run enrichment with NVD mocked out — we only care about the
        # sweep at the end. enrich_service is called per-service, so
        # we return an empty result (no new CVEs) and let the function
        # reach its orphan-cleanup tail.
        from cauldron.ai.cve_enricher import EnrichmentResult
        with patch(
            "cauldron.ai.cve_enricher.enrich_service",
            return_value=EnrichmentResult(product="nginx", version="1.18.0", cves=[]),
        ):
            stats = enrich_services_from_graph()

        assert stats.get("orphans_removed", 0) == 1
        with get_session() as session:
            remaining = [r["cve"] for r in session.run(
                "MATCH (v:Vulnerability) RETURN v.cve_id AS cve ORDER BY cve"
            )]
            assert remaining == ["CVE-9999-LINKED"]


