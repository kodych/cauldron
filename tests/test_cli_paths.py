"""CLI paths-command tests.

Focused on the dedupe helper that the renderer relies on so multi-port
findings collapse into one printed row (matching the web UI behaviour).
Pure unit tests — no Neo4j, no rich console, no DB fixtures.
"""

from __future__ import annotations

from cauldron.ai.attack_paths import VulnInfo
from cauldron.cli.commands import _dedupe_vulns_by_cve


def _vuln(
    cve_id: str,
    *,
    port: int | None = None,
    confidence: str = "check",
    has_exploit: bool = False,
    in_cisa_kev: bool = False,
    cvss: float = 7.5,
    title: str = "",
) -> VulnInfo:
    return VulnInfo(
        cve_id=cve_id, cvss=cvss, has_exploit=has_exploit, title=title,
        confidence=confidence, port=port, in_cisa_kev=in_cisa_kev,
    )


class TestDedupeVulnsByCve:
    def test_single_cve_single_port(self):
        out = _dedupe_vulns_by_cve([_vuln("CVE-2024-0001", port=445)])
        assert len(out) == 1
        assert out[0]["vuln"].cve_id == "CVE-2024-0001"
        assert out[0]["ports"] == [445]

    def test_same_cve_three_ports_collapsed(self):
        """PetitPotam on a DC: emitted as three VulnInfo entries (88,
        135, 445). The renderer must show ONE row with the port set
        rolled in, not three identical rows."""
        out = _dedupe_vulns_by_cve([
            _vuln("CVE-2021-36942", port=88, has_exploit=True),
            _vuln("CVE-2021-36942", port=135, has_exploit=True),
            _vuln("CVE-2021-36942", port=445, has_exploit=True),
        ])
        assert len(out) == 1
        assert out[0]["vuln"].cve_id == "CVE-2021-36942"
        assert out[0]["ports"] == [88, 135, 445]
        assert out[0]["has_exploit"] is True

    def test_distinct_cves_preserved_in_order(self):
        """Distinct CVEs must keep their input order — the caller has
        already sorted by priority (confirmed > likely > check then by
        cvss) and the helper must not shuffle that."""
        out = _dedupe_vulns_by_cve([
            _vuln("CVE-2022-0001", confidence="confirmed"),
            _vuln("CVE-2022-0002", confidence="likely"),
            _vuln("CVE-2022-0003", confidence="check"),
        ])
        assert [g["vuln"].cve_id for g in out] == [
            "CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0003",
        ]

    def test_confidence_promotion_picks_strongest_representative(self):
        """When the same CVE appears with different confidence levels
        across ports (rare but possible — e.g. one port had a script
        confirmation, another didn't), the representative gets promoted
        to the strongest tier so the row renders with the right label."""
        out = _dedupe_vulns_by_cve([
            _vuln("CVE-2024-1234", port=80, confidence="check"),
            _vuln("CVE-2024-1234", port=443, confidence="confirmed"),
        ])
        assert len(out) == 1
        assert out[0]["vuln"].confidence == "confirmed"
        assert out[0]["vuln"].port == 443
        assert out[0]["ports"] == [80, 443]

    def test_has_exploit_or_merged_across_ports(self):
        """If any port-instance is marked has_exploit, the merged
        entry must reflect that — the renderer uses this merged flag
        to decide between EXPLOIT/CVSS labels, and a confirmed exploit
        on one port shouldn't be hidden because the representative
        landed on a port where has_exploit was False."""
        out = _dedupe_vulns_by_cve([
            _vuln("CVE-2024-5678", port=80, has_exploit=False),
            _vuln("CVE-2024-5678", port=443, has_exploit=True),
        ])
        assert out[0]["has_exploit"] is True

    def test_kev_or_merged_across_ports(self):
        out = _dedupe_vulns_by_cve([
            _vuln("CVE-2024-9999", port=80, in_cisa_kev=False),
            _vuln("CVE-2024-9999", port=443, in_cisa_kev=True),
        ])
        assert out[0]["in_cisa_kev"] is True

    def test_port_none_does_not_pollute_set(self):
        """Vulns with no port (e.g. host-level findings) merge into
        the group without adding noise to the port list. The port set
        stays empty so the renderer shows just the host IP, no colon."""
        out = _dedupe_vulns_by_cve([
            _vuln("CVE-2024-AAAA", port=None),
            _vuln("CVE-2024-AAAA", port=None),
        ])
        assert len(out) == 1
        assert out[0]["ports"] == []

    def test_empty_input_returns_empty(self):
        assert _dedupe_vulns_by_cve([]) == []
