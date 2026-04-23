"""Unit tests for report helpers.

These cover the pure-Python helpers that do not require a Neo4j connection:
  - IP list CIDR compression
  - CVE priority sort (KEV, has_exploit, CVSS)
  - Markdown -> HTML inline conversion (escaping, autolinks, italics with
    word-boundary safety so CPE/URL underscores survive)
"""

from __future__ import annotations

from cauldron.report import (
    _compress_ip_list,
    _cve_priority_tuple,
    _md_inline,
)


# ---------------------------------------------------------------------------
# _compress_ip_list
# ---------------------------------------------------------------------------

def test_compress_ip_list_empty():
    assert _compress_ip_list([]) == ""


def test_compress_ip_list_single():
    assert _compress_ip_list(["10.0.0.1"]) == "10.0.0.1"


def test_compress_ip_list_contiguous_range():
    ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert _compress_ip_list(ips) == "10.0.0.1-3"


def test_compress_ip_list_mixed_ranges_and_singles():
    ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.7"]
    assert _compress_ip_list(ips) == "10.0.0.1-3, 10.0.0.7"


def test_compress_ip_list_multiple_subnets():
    ips = ["10.10.20.1", "10.10.20.2", "10.10.20.3", "10.10.21.4"]
    assert _compress_ip_list(ips) == "10.10.20.1-3, 10.10.21.4"


def test_compress_ip_list_deduplicates():
    ips = ["10.0.0.1", "10.0.0.1", "10.0.0.2"]
    assert _compress_ip_list(ips) == "10.0.0.1-2"


def test_compress_ip_list_unsorted_input():
    # Client might hand us hostnames or out-of-order IPs; output must be stable.
    ips = ["10.0.0.3", "10.0.0.1", "10.0.0.2"]
    assert _compress_ip_list(ips) == "10.0.0.1-3"


def test_compress_ip_list_non_ipv4_passthrough():
    # Non-IPv4 strings (e.g., IPv6 or hostnames) are preserved unchanged.
    ips = ["10.0.0.1", "10.0.0.2", "host.local"]
    result = _compress_ip_list(ips)
    assert "10.0.0.1-2" in result
    assert "host.local" in result


def test_compress_ip_list_preserves_all_addresses():
    # No matter how large the input, every IP must appear in the output.
    ips = [f"10.0.1.{i}" for i in range(1, 51)]
    result = _compress_ip_list(ips)
    assert "10.0.1.1-50" == result


# ---------------------------------------------------------------------------
# _cve_priority_tuple — KEV first, then exploit, then CVSS desc
# ---------------------------------------------------------------------------

def test_priority_kev_beats_exploit():
    kev = {"in_cisa_kev": True, "has_exploit": False, "cvss": 5.0}
    exp = {"in_cisa_kev": False, "has_exploit": True, "cvss": 9.8}
    # Sorting ascending → kev comes first.
    assert _cve_priority_tuple(kev) < _cve_priority_tuple(exp)


def test_priority_exploit_beats_plain_critical():
    exp = {"in_cisa_kev": False, "has_exploit": True, "cvss": 7.0}
    crit = {"in_cisa_kev": False, "has_exploit": False, "cvss": 10.0}
    assert _cve_priority_tuple(exp) < _cve_priority_tuple(crit)


def test_priority_cvss_tiebreaker():
    high = {"in_cisa_kev": False, "has_exploit": False, "cvss": 9.0}
    low = {"in_cisa_kev": False, "has_exploit": False, "cvss": 5.0}
    assert _cve_priority_tuple(high) < _cve_priority_tuple(low)


def test_priority_handles_missing_fields():
    # Defensive: Neo4j may return None for unscored CVEs.
    empty = {}
    full = {"in_cisa_kev": True, "has_exploit": True, "cvss": 9.8}
    assert _cve_priority_tuple(full) < _cve_priority_tuple(empty)


# ---------------------------------------------------------------------------
# _md_inline — HTML-escape, autolinks, word-boundary italics
# ---------------------------------------------------------------------------

def test_md_inline_escapes_html():
    # Raw < and > should be escaped so user data can't inject markup.
    assert _md_inline("1 < 2 & b > a") == "1 &lt; 2 &amp; b &gt; a"


def test_md_inline_bold():
    assert _md_inline("**EXPLOIT**") == "<strong>EXPLOIT</strong>"


def test_md_inline_code():
    assert _md_inline("use `nmap -sV`") == "use <code>nmap -sV</code>"


def test_md_inline_autolink_https():
    # `<https://...>` markdown autolink -> clickable anchor.
    out = _md_inline("See <https://example.com/x?a=1>")
    assert '<a href="https://example.com/x?a=1">https://example.com/x?a=1</a>' in out


def test_md_inline_autolink_with_underscores():
    # Underscores in URL path must survive (no italic eating).
    url = "https://github.com/foo/exploit_bar_baz/blob/main/x"
    out = _md_inline(f"Exploit: <{url}>")
    assert f'<a href="{url}">{url}</a>' in out
    assert "<em>" not in out


def test_md_inline_italic_word_boundary():
    # `_text_` at a word boundary IS italic.
    assert _md_inline("_Confidence: high_") == "<em>Confidence: high</em>"


def test_md_inline_italic_skips_internal_underscores():
    # Function/CPE names with inner underscores must NOT become italic.
    src = "krb5_pac_parse heap overflow"
    out = _md_inline(src)
    assert "<em>" not in out
    assert "krb5_pac_parse" in out


def test_md_inline_italic_skips_cpe_strings():
    src = "CPE cpe:2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*"
    out = _md_inline(src)
    assert "<em>" not in out


def test_md_inline_combined():
    src = "**KEV** · `cve-2024-1234` at <https://nvd.nist.gov/vuln/detail/CVE-2024-1234>"
    out = _md_inline(src)
    assert "<strong>KEV</strong>" in out
    assert "<code>cve-2024-1234</code>" in out
    assert '<a href="https://nvd.nist.gov/vuln/detail/CVE-2024-1234"' in out
