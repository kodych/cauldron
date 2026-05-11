"""Tests for the banner-token CPE resolver.

The resolver lives in cauldron.ai.cve_enricher. It tokenizes banner-shaped
strings (compound products, extrainfo, NSE script output) into (name, version)
pairs and resolves each to a canonical NVD CPE 2.3 via NVD's CPE Dictionary
API. The dictionary IS the lookup table, so we don't maintain a static
mapping that drifts.

These tests are DB-safe: they mock all NVD HTTP calls and don't touch Neo4j,
so running them against a graph with loaded engagement data is harmless.
"""

from __future__ import annotations

import json
import urllib.error
from io import BytesIO
from unittest.mock import patch

import pytest


# --- Tokenizer -------------------------------------------------------------


class TestExtractBannerTokens:
    def test_simple_single_token(self):
        from cauldron.ai.cve_enricher import _extract_banner_tokens
        assert _extract_banner_tokens("OpenSSL/0.9.6b") == [("OpenSSL", "0.9.6b")]

    def test_compound_kioptrix_443_banner(self):
        from cauldron.ai.cve_enricher import _extract_banner_tokens
        banner = "Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b"
        assert _extract_banner_tokens(banner) == [
            ("Apache", "1.3.20"),
            ("mod_ssl", "2.8.4"),
            ("OpenSSL", "0.9.6b"),
        ]

    def test_redhat_linux_not_extracted_version_must_be_numeric(self):
        # "Red-Hat/Linux" has a non-digit "version" segment and must not match.
        # This is the self-filtering guard: garbage like "Red-Hat/Linux" or
        # "Powered-By/Cauldron" never makes it to the NVD resolver.
        from cauldron.ai.cve_enricher import _extract_banner_tokens
        assert _extract_banner_tokens("Red-Hat/Linux Powered-By/Cauldron") == []

    def test_single_letter_name_rejected(self):
        from cauldron.ai.cve_enricher import _extract_banner_tokens
        # Names shorter than 2 chars are rejected by the regex to drop noise.
        assert _extract_banner_tokens("X/1.0") == []
        assert _extract_banner_tokens("Xy/1.0") == [("Xy", "1.0")]

    def test_dedup_across_multiple_sources(self):
        from cauldron.ai.cve_enricher import _extract_banner_tokens
        # mod_ssl/2.8.4 appears in product, extrainfo, and script_http_server_header.
        # The tokenizer must dedup so the resolver isn't called three times.
        out = _extract_banner_tokens(
            "Apache/1.3.20 mod_ssl/2.8.4",
            "(Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b",
            "Apache/1.3.20 (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b",
        )
        assert out == [
            ("Apache", "1.3.20"),
            ("mod_ssl", "2.8.4"),
            ("OpenSSL", "0.9.6b"),
        ]

    def test_none_sources_skipped(self):
        from cauldron.ai.cve_enricher import _extract_banner_tokens
        assert _extract_banner_tokens(None, "mod_ssl/2.8.4", None) == [("mod_ssl", "2.8.4")]

    def test_dedup_case_insensitive_on_name(self):
        from cauldron.ai.cve_enricher import _extract_banner_tokens
        # ModSSL/2.8.4 and mod_ssl/2.8.4 are different name strings but
        # the resolver downstream lowercases names — we already dedup by
        # (lower-name, version) so the second is dropped here.
        out = _extract_banner_tokens("OpenSSL/0.9.6b openssl/0.9.6b")
        assert out == [("OpenSSL", "0.9.6b")]


# --- Resolver --------------------------------------------------------------


def _mock_response(payload: dict) -> BytesIO:
    return BytesIO(json.dumps(payload).encode("utf-8"))


def _cpe_response(cpe_names: list[str]) -> dict:
    return {"products": [{"cpe": {"cpeName": c}} for c in cpe_names]}


@pytest.fixture(autouse=True)
def _reset_resolver_cache():
    """Clear the session-scoped resolver cache between tests."""
    from cauldron.ai.cve_enricher import _cpe_resolution_cache
    _cpe_resolution_cache.clear()
    yield
    _cpe_resolution_cache.clear()


class TestResolveBannerToken:
    def test_match_returns_vendor_wildcarded_cpe(self):
        from cauldron.ai.cve_enricher import _resolve_banner_token
        # NVD dictionary's canonical entry is openssl:openssl:0.9.6b, but
        # the resolver returns the *vendor-wildcarded* form -- see the
        # function docstring for why (historic CVEs may use different
        # vendor strings for the same product, e.g. mod_ssl Slapper).
        payload = _cpe_response(["cpe:2.3:a:openssl:openssl:0.9.6b:*:*:*:*:*:*:*"])
        with patch("urllib.request.urlopen") as m:
            m.return_value.__enter__.return_value.read.return_value = json.dumps(payload).encode()
            result = _resolve_banner_token("OpenSSL", "0.9.6b")
        assert result == "cpe:2.3:a:*:openssl:0.9.6b:*:*:*:*:*:*:*"

    def test_returns_wildcard_regardless_of_canonical_vendor(self):
        from cauldron.ai.cve_enricher import _resolve_banner_token
        # mod_ssl is the canonical NVD inconsistency: dictionary entry is
        # filed under vendor `modssl`, but the 2002-era CVE records use
        # vendor `mod_ssl`. A canonical-form return would miss
        # CVE-2002-0082; the wildcard form catches both.
        payload = _cpe_response(["cpe:2.3:a:modssl:mod_ssl:2.8.4:*:*:*:*:*:*:*"])
        with patch("urllib.request.urlopen") as m:
            m.return_value.__enter__.return_value.read.return_value = json.dumps(payload).encode()
            result = _resolve_banner_token("mod_ssl", "2.8.4")
        assert result == "cpe:2.3:a:*:mod_ssl:2.8.4:*:*:*:*:*:*:*"

    def test_nginx_returns_wildcard_even_with_multiple_vendors(self):
        from cauldron.ai.cve_enricher import _resolve_banner_token
        # nginx CVEs are filed under f5:nginx in NVD's actual CVE records
        # (F5 acquired nginx), but the dictionary still lists nginx:nginx.
        # Wildcard form captures both via downstream virtualMatchString.
        payload = _cpe_response([
            "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
        ])
        with patch("urllib.request.urlopen") as m:
            m.return_value.__enter__.return_value.read.return_value = json.dumps(payload).encode()
            result = _resolve_banner_token("nginx", "1.18.0")
        assert result == "cpe:2.3:a:*:nginx:1.18.0:*:*:*:*:*:*:*"

    def test_zero_hits_returns_none_and_caches(self):
        from cauldron.ai.cve_enricher import _cpe_resolution_cache, _resolve_banner_token
        payload = _cpe_response([])
        with patch("urllib.request.urlopen") as m:
            m.return_value.__enter__.return_value.read.return_value = json.dumps(payload).encode()
            result = _resolve_banner_token("Red-Hat", "9.0")
            assert result is None
            # Second call must not hit the network — the empty sentinel sits in
            # the cache so junk tokens don't burn API budget on every scan.
            result2 = _resolve_banner_token("Red-Hat", "9.0")
            assert result2 is None
            assert m.call_count == 1
        assert ("red-hat", "9.0") in _cpe_resolution_cache

    def test_drops_operating_system_typed_cpes(self):
        from cauldron.ai.cve_enricher import _resolve_banner_token
        # NVD may return o:-typed (OS) CPEs for some keyword queries; we
        # tokenize application banners and want application CPEs only.
        payload = _cpe_response([
            "cpe:2.3:o:redhat:linux:9.0:*:*:*:*:*:*:*",
        ])
        with patch("urllib.request.urlopen") as m:
            m.return_value.__enter__.return_value.read.return_value = json.dumps(payload).encode()
            result = _resolve_banner_token("Linux", "9.0")
        assert result is None

    def test_session_cache_hit_skips_network(self):
        from cauldron.ai.cve_enricher import _resolve_banner_token
        payload = _cpe_response(["cpe:2.3:a:openssl:openssl:0.9.6b:*:*:*:*:*:*:*"])
        with patch("urllib.request.urlopen") as m:
            m.return_value.__enter__.return_value.read.return_value = json.dumps(payload).encode()
            r1 = _resolve_banner_token("OpenSSL", "0.9.6b")
            r2 = _resolve_banner_token("OpenSSL", "0.9.6b")
            r3 = _resolve_banner_token("openssl", "0.9.6b")  # case-insensitive key
            assert r1 == r2 == r3
            assert m.call_count == 1


class TestResolverRetryOn429:
    def test_retries_twice_then_succeeds(self):
        from cauldron.ai.cve_enricher import _resolve_banner_token
        payload = _cpe_response(["cpe:2.3:a:openssl:openssl:0.9.6b:*:*:*:*:*:*:*"])

        # Two 429s, then a success. The resolver should sleep 6 s / 12 s
        # between attempts and pick up the third.
        call_count = {"n": 0}

        def fake_urlopen(req, timeout=15):
            call_count["n"] += 1
            if call_count["n"] <= 2:
                raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", {}, None)

            class _Resp:
                def __enter__(self): return self
                def __exit__(self, *a): pass
                def read(self): return json.dumps(payload).encode()
            return _Resp()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen), \
             patch("time.sleep") as mock_sleep:   # don't actually sleep
            result = _resolve_banner_token("OpenSSL", "0.9.6b")
        # Resolver returns the vendor-wildcarded form regardless of what the
        # NVD dictionary canonicalizes the entry as -- see docstring.
        assert result == "cpe:2.3:a:*:openssl:0.9.6b:*:*:*:*:*:*:*"
        assert call_count["n"] == 3
        # First retry sleeps 6 s, second sleeps 12 s. Other sleeps come from
        # _rate_limit (small, variable per system); just verify the backoff
        # values were requested.
        backoff_durations = [c.args[0] for c in mock_sleep.call_args_list if c.args[0] in (6.0, 12.0)]
        assert backoff_durations == [6.0, 12.0]

    def test_gives_up_after_third_429_and_caches_not_found(self):
        from cauldron.ai.cve_enricher import _cpe_resolution_cache, _resolve_banner_token

        def always_429(req, timeout=15):
            raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", {}, None)

        with patch("urllib.request.urlopen", side_effect=always_429), patch("time.sleep"):
            result = _resolve_banner_token("OpenSSL", "0.9.6b")
        assert result is None
        # After three 429s in a row the resolver caches the failure so
        # subsequent calls don't keep hammering NVD.
        assert _cpe_resolution_cache.get(("openssl", "0.9.6b")) == ""

    def test_non_429_http_error_caches_immediately(self):
        from cauldron.ai.cve_enricher import _cpe_resolution_cache, _resolve_banner_token

        def http_500(req, timeout=15):
            raise urllib.error.HTTPError(req.full_url, 500, "Server Error", {}, None)

        with patch("urllib.request.urlopen", side_effect=http_500), patch("time.sleep") as mock_sleep:
            result = _resolve_banner_token("Foo", "1.0")
        assert result is None
        # No backoff sleeps — non-429 errors aren't retryable. _rate_limit may
        # have called sleep once for the throttle, but we should not see the
        # 6.0/12.0 backoff durations.
        backoff_calls = [c for c in mock_sleep.call_args_list if c.args[0] in (6.0, 12.0)]
        assert backoff_calls == []
        assert _cpe_resolution_cache.get(("foo", "1.0")) == ""

    def test_transient_url_error_does_not_cache(self):
        from cauldron.ai.cve_enricher import _cpe_resolution_cache, _resolve_banner_token

        def url_error(req, timeout=15):
            raise urllib.error.URLError("network down")

        with patch("urllib.request.urlopen", side_effect=url_error), patch("time.sleep"):
            result = _resolve_banner_token("Foo", "1.0")
        assert result is None
        # Transient — next caller may succeed. Cache must stay empty so we
        # don't pin a wrong "not found" for the rest of the session.
        assert ("foo", "1.0") not in _cpe_resolution_cache


# --- Candidate builder -----------------------------------------------------


class TestBuildCpeCandidates:
    def test_primary_cpe_only_when_no_subproducts(self):
        from cauldron.ai.cve_enricher import _build_cpe_candidates
        # Service with nmap-emitted CPE, no extra_info, no compound banner.
        # No resolver calls needed.
        with patch("cauldron.ai.cve_enricher._resolve_banner_token") as resolver:
            cands = _build_cpe_candidates(
                ["cpe:/a:openbsd:openssh:7.4p1"],
                product="OpenSSH",
                version="7.4p1",
            )
        assert cands == ["cpe:2.3:a:openbsd:openssh:7.4p1:*:*:*:*:*:*:*"]
        resolver.assert_not_called()

    def test_kioptrix_443_compound_product_resolves_subproducts(self):
        from cauldron.ai.cve_enricher import _build_cpe_candidates

        # Mock resolver: pretend NVD knows mod_ssl and openssl but not Apache
        # (because NVD's product name is http_server, not apache). Returns
        # the vendor-wildcarded form -- see _resolve_banner_token docstring.
        def fake_resolve(name, version):
            mapping = {
                ("apache", "1.3.20"): None,
                ("mod_ssl", "2.8.4"): "cpe:2.3:a:*:mod_ssl:2.8.4:*:*:*:*:*:*:*",
                ("openssl", "0.9.6b"): "cpe:2.3:a:*:openssl:0.9.6b:*:*:*:*:*:*:*",
            }
            return mapping.get((name.lower(), version))

        with patch("cauldron.ai.cve_enricher._resolve_banner_token", side_effect=fake_resolve):
            cands = _build_cpe_candidates(
                cpe_list=[],
                product="Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b",
                version=None,
            )
        # No primary CPE (compound product, no PRODUCT_CPE_MAP match) -- the
        # full set comes from sub-product resolution.
        assert "cpe:2.3:a:*:mod_ssl:2.8.4:*:*:*:*:*:*:*" in cands
        assert "cpe:2.3:a:*:openssl:0.9.6b:*:*:*:*:*:*:*" in cands

    def test_kioptrix_80_extrainfo_resolves_subproducts(self):
        from cauldron.ai.cve_enricher import _build_cpe_candidates

        def fake_resolve(name, version):
            mapping = {
                ("mod_ssl", "2.8.4"): "cpe:2.3:a:*:mod_ssl:2.8.4:*:*:*:*:*:*:*",
                ("openssl", "0.9.6b"): "cpe:2.3:a:*:openssl:0.9.6b:*:*:*:*:*:*:*",
            }
            return mapping.get((name.lower(), version))

        with patch("cauldron.ai.cve_enricher._resolve_banner_token", side_effect=fake_resolve):
            cands = _build_cpe_candidates(
                cpe_list=["cpe:/a:apache:http_server:1.3.20"],
                product="Apache httpd",
                version="1.3.20",
                extra_info="(Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b",
            )
        # Primary CPE (nmap-emitted) first, then resolved sub-products.
        assert cands[0] == "cpe:2.3:a:apache:http_server:1.3.20:*:*:*:*:*:*:*"
        assert "cpe:2.3:a:*:mod_ssl:2.8.4:*:*:*:*:*:*:*" in cands
        assert "cpe:2.3:a:*:openssl:0.9.6b:*:*:*:*:*:*:*" in cands

    def test_simple_product_skips_compound_tokenization(self):
        from cauldron.ai.cve_enricher import _build_cpe_candidates

        # "Apache httpd" has only one token slot ("httpd" doesn't have a
        # version after a slash) so it shouldn't be tokenized as compound.
        # The resolver must not be called.
        with patch("cauldron.ai.cve_enricher._resolve_banner_token") as resolver:
            _build_cpe_candidates(
                cpe_list=["cpe:/a:apache:http_server:1.3.20"],
                product="Apache httpd",
                version="1.3.20",
            )
        resolver.assert_not_called()

    def test_script_outputs_are_tokenized(self):
        from cauldron.ai.cve_enricher import _build_cpe_candidates

        def fake_resolve(name, version):
            return (
                "cpe:2.3:a:samba:samba:2.2.1a:*:*:*:*:*:*:*"
                if (name.lower(), version) == ("samba", "2.2.1a") else None
            )

        with patch("cauldron.ai.cve_enricher._resolve_banner_token", side_effect=fake_resolve):
            cands = _build_cpe_candidates(
                cpe_list=["cpe:/a:samba:samba"],
                product="Samba smbd",
                version=None,
                script_outputs=["OS: Unix (Samba 2.2.1a)\n  Workgroup: MYGROUP"],
            )
        # Script output isn't quite the "Name/Version" banner shape — the
        # smb-os-discovery format is "Samba 2.2.1a" (space-separated). This
        # test documents that the current tokenizer DOES NOT catch that
        # form: smb-os-discovery needs a dedicated extractor in a future
        # iteration. For now the test asserts that the standard Name/Version
        # tokens are still tried, and the samba wildcard CPE passes through.
        assert "cpe:2.3:a:samba:samba:*:*:*:*:*:*:*:*" in cands

    def test_dedupes_nmap_emitted_against_primary(self):
        from cauldron.ai.cve_enricher import _build_cpe_candidates

        # nmap_emitted CPE makes its way in twice -- once via the primary
        # selection in _get_cpe_for_service, once via the explicit
        # _cpe22_to_23 conversion loop. The candidate builder must dedup
        # so we don't fire the same NVD query twice.
        with patch("cauldron.ai.cve_enricher._resolve_banner_token", return_value=None):
            cands = _build_cpe_candidates(
                cpe_list=["cpe:/a:apache:http_server:1.3.20"],
                product="Apache httpd",
                version="1.3.20",
            )
        assert cands.count("cpe:2.3:a:apache:http_server:1.3.20:*:*:*:*:*:*:*") == 1


# --- has_exploit URL detection --------------------------------------------
#
# CVE-2002-0082 and similar pre-2010 CVEs have real PoCs hosted on
# packetstormsecurity.com or Metasploit modules at rapid7.com/db/modules/,
# but NVD doesn't tag those references with the "Exploit" attribute (the
# tag system was retrofitted unevenly). Cauldron's _parse_cve extends
# detection with path-scoped patterns for those two hosts -- path-scoped
# because the bare domains host plenty of non-exploit content.


def _ref(url: str, tags: list[str] | None = None) -> dict:
    return {"url": url, "tags": tags or []}


def _cve_with_refs(refs: list[dict]) -> dict:
    """Minimal NVD CVE structure -- only fields _parse_cve actually reads."""
    return {
        "id": "CVE-2099-0000",
        "descriptions": [{"lang": "en", "value": "test"}],
        "metrics": {},
        "references": refs,
        "weaknesses": [],
        "published": "2020-01-01T00:00:00",
    }


class TestHasExploitUrlDetection:
    def test_exploit_db_already_supported(self):
        from cauldron.ai.cve_enricher import _parse_cve
        cve = _parse_cve(_cve_with_refs([
            _ref("https://www.exploit-db.com/exploits/12345"),
        ]))
        assert cve.has_exploit is True
        assert cve.exploit_url == "https://www.exploit-db.com/exploits/12345"

    def test_github_exploit_already_supported(self):
        from cauldron.ai.cve_enricher import _parse_cve
        cve = _parse_cve(_cve_with_refs([
            _ref("https://github.com/some-researcher/CVE-2099-0000-exploit"),
        ]))
        assert cve.has_exploit is True

    def test_packetstorm_files_path_detected(self):
        from cauldron.ai.cve_enricher import _parse_cve
        # The CVE-2002-0082 (Slapper) reference: PoC archived on packetstorm
        # under /files/<id>/<descriptive-name>.html. NVD does not tag this
        # as Exploit, but it is a real PoC and should count.
        cve = _parse_cve(_cve_with_refs([
            _ref("http://packetstormsecurity.com/files/153567/"
                 "Apache-mod_ssl-OpenSSL-Remote-Buffer-Overflow.html"),
        ]))
        assert cve.has_exploit is True

    def test_packetstorm_bare_domain_not_detected(self):
        from cauldron.ai.cve_enricher import _parse_cve
        # Path scoping: news / front-page / non-files URLs on packetstorm
        # are advisory mirrors and discussion, not PoC. Must not flip
        # has_exploit on their own.
        cve = _parse_cve(_cve_with_refs([
            _ref("https://packetstormsecurity.com/news/view/12345/some-news"),
        ]))
        assert cve.has_exploit is False

    def test_rapid7_metasploit_module_path_detected(self):
        from cauldron.ai.cve_enricher import _parse_cve
        cve = _parse_cve(_cve_with_refs([
            _ref("https://www.rapid7.com/db/modules/exploit/linux/"
                 "http/apache_mod_ssl_bof/"),
        ]))
        assert cve.has_exploit is True

    def test_rapid7_marketing_url_not_detected(self):
        from cauldron.ai.cve_enricher import _parse_cve
        # rapid7.com has plenty of marketing pages, vulnerability DB entries
        # (not modules), and blog posts. Only the /db/modules/exploit/ path
        # is the Metasploit-exploit catalog.
        cve = _parse_cve(_cve_with_refs([
            _ref("https://www.rapid7.com/blog/post/2023/something/"),
            _ref("https://www.rapid7.com/db/vulnerabilities/some-vuln/"),
        ]))
        assert cve.has_exploit is False

    def test_explicit_nvd_tag_wins_over_url_check(self):
        from cauldron.ai.cve_enricher import _parse_cve
        # When NVD has already tagged a reference as Exploit, that wins
        # immediately -- we trust NVD's own curation over URL heuristics.
        cve = _parse_cve(_cve_with_refs([
            _ref("https://example.com/anything", tags=["Exploit"]),
            _ref("http://packetstormsecurity.com/files/12345/whatever.html"),
        ]))
        assert cve.has_exploit is True
        assert cve.exploit_url == "https://example.com/anything"

    def test_case_insensitive_url_match(self):
        from cauldron.ai.cve_enricher import _parse_cve
        # Mixed-case URLs should still match -- old references on
        # packetstormsecurity.com / rapid7.com use varied capitalization.
        cve = _parse_cve(_cve_with_refs([
            _ref("HTTP://PACKETSTORMSECURITY.COM/files/99999/Foo.html"),
        ]))
        assert cve.has_exploit is True

    def test_no_exploit_reference_stays_false(self):
        from cauldron.ai.cve_enricher import _parse_cve
        # Pre-2010 era CVE references: vendor advisories, mailing lists,
        # patch URLs. None should flip has_exploit.
        cve = _parse_cve(_cve_with_refs([
            _ref("http://www.redhat.com/support/errata/RHSA-2002-045.html"),
            _ref("http://www.securityfocus.com/bid/4189"),
            _ref("http://marc.info/?l=bugtraq&m=101518491916936&w=2"),
        ]))
        assert cve.has_exploit is False
        assert cve.exploit_url is None
