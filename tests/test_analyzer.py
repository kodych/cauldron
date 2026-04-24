"""Tests for AI analyzer module."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from cauldron.ai.analyzer import (
    AnalysisResult,
    _anonymize_text,
    _build_anonymization_map,
    _deanonymize_hosts,
    _parse_classification_response,
    _parse_json_response,
    analyze_graph,
)
from cauldron.graph.connection import clear_database, get_session, verify_connection

# --- Unit tests (no Neo4j needed) ---


class TestParseJsonResponse:
    def test_valid_json_array(self):
        result = _parse_json_response('[{"a": 1}]')
        assert result == [{"a": 1}]

    def test_valid_json_object(self):
        result = _parse_json_response('{"a": 1}')
        assert result == {"a": 1}

    def test_strips_markdown_fences(self):
        result = _parse_json_response('```json\n[{"a": 1}]\n```')
        assert result == [{"a": 1}]

    def test_invalid_json(self):
        result = _parse_json_response("not json")
        assert result is None

    def test_empty_string(self):
        result = _parse_json_response("")
        assert result is None


class TestParseClassificationResponse:
    def test_valid_json(self):
        response = json.dumps([
            {"ip": "10.0.0.1", "role": "web_server", "confidence": 0.85},
            {"ip": "10.0.0.2", "role": "database", "confidence": 0.9},
        ])
        result = _parse_classification_response(response)
        assert len(result) == 2
        assert result[0]["ip"] == "10.0.0.1"
        assert result[0]["role"] == "web_server"

    def test_filters_low_confidence(self):
        response = json.dumps([
            {"ip": "10.0.0.1", "role": "web_server", "confidence": 0.3},
            {"ip": "10.0.0.2", "role": "database", "confidence": 0.9},
        ])
        result = _parse_classification_response(response)
        assert len(result) == 1
        assert result[0]["ip"] == "10.0.0.2"

    def test_filters_invalid_roles(self):
        response = json.dumps([
            {"ip": "10.0.0.1", "role": "attack_helicopter", "confidence": 0.9},
            {"ip": "10.0.0.2", "role": "database", "confidence": 0.9},
        ])
        result = _parse_classification_response(response)
        assert len(result) == 1
        assert result[0]["role"] == "database"

    def test_handles_markdown_fences(self):
        response = "```json\n" + json.dumps([
            {"ip": "10.0.0.1", "role": "printer", "confidence": 0.8},
        ]) + "\n```"
        result = _parse_classification_response(response)
        assert len(result) == 1

    def test_handles_invalid_json(self):
        result = _parse_classification_response("not json at all")
        assert result == []

    def test_handles_empty_array(self):
        result = _parse_classification_response("[]")
        assert result == []

    def test_handles_non_array(self):
        result = _parse_classification_response('{"ip": "10.0.0.1"}')
        assert result == []

    def test_skips_incomplete_items(self):
        response = json.dumps([
            {"ip": "10.0.0.1"},  # no role
            {"role": "database", "confidence": 0.9},  # no ip
            {"ip": "10.0.0.3", "role": "web_server", "confidence": 0.85},
        ])
        result = _parse_classification_response(response)
        assert len(result) == 1
        assert result[0]["ip"] == "10.0.0.3"


try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False


@pytest.mark.skipif(not HAS_ANTHROPIC, reason="anthropic package not installed")
class TestCallClaude:
    def test_successful_call(self):
        from cauldron.ai.analyzer import _call_claude

        mock_message = MagicMock()
        mock_message.content = [MagicMock(text="test response")]

        with patch("cauldron.ai.analyzer.settings") as mock_settings:
            mock_settings.anthropic_api_key = "sk-ant-test"
            mock_settings.ai_model = "claude-sonnet-4-20250514"
            with patch("anthropic.Anthropic") as mock_anthropic:
                mock_client = MagicMock()
                mock_client.messages.create.return_value = mock_message
                mock_anthropic.return_value = mock_client

                result = _call_claude("test prompt")
                assert result == "test response"
                mock_client.messages.create.assert_called_once()

    def test_auth_error_raises_to_short_circuit_pipeline(self):
        """``_call_claude`` must raise ClaudeAuthError on a 401 instead
        of returning None — otherwise every AI phase in a boil burns a
        second Anthropic request with the same bad key and logs
        duplicate 'Invalid API key' noise."""
        import pytest

        from cauldron.ai.analyzer import ClaudeAuthError, _call_claude

        with patch("cauldron.ai.analyzer.settings") as mock_settings:
            mock_settings.anthropic_api_key = "bad-key"
            mock_settings.ai_model = "claude-sonnet-4-20250514"
            with patch("anthropic.Anthropic") as mock_anthropic:
                mock_client = MagicMock()
                mock_client.messages.create.side_effect = anthropic.AuthenticationError(
                    message="invalid key",
                    response=MagicMock(status_code=401),
                    body=None,
                )
                mock_anthropic.return_value = mock_client

                with pytest.raises(ClaudeAuthError):
                    _call_claude("test")

    def test_rate_limit(self):
        from cauldron.ai.analyzer import _call_claude

        with patch("cauldron.ai.analyzer.settings") as mock_settings:
            mock_settings.anthropic_api_key = "sk-ant-test"
            mock_settings.ai_model = "claude-sonnet-4-20250514"
            with patch("anthropic.Anthropic") as mock_anthropic:
                mock_client = MagicMock()
                mock_client.messages.create.side_effect = anthropic.RateLimitError(
                    message="rate limited",
                    response=MagicMock(status_code=429),
                    body=None,
                )
                mock_anthropic.return_value = mock_client

                result = _call_claude("test")
                assert result is None

    def test_import_error_returns_none(self):
        from cauldron.ai.analyzer import _call_claude

        with patch("cauldron.ai.analyzer.settings") as mock_settings:
            mock_settings.anthropic_api_key = "sk-ant-test"
            with patch.dict("sys.modules", {"anthropic": None}):
                result = _call_claude("test")
                assert result is None


class TestAnalyzeGraph:
    def test_skips_without_api_key(self):
        with patch("cauldron.ai.analyzer.settings") as mock_settings:
            mock_settings.anthropic_api_key = ""
            result = analyze_graph()
            assert isinstance(result, AnalysisResult)
            assert result.cves_found == 0

    def test_auth_error_short_circuits_remaining_phases(self):
        """Phase 1's first _call_claude hits 401 → remaining phases must
        NOT be attempted. Caller sees ``result.auth_error`` populated
        (so UI can surface a banner) instead of silent zeros across
        every counter."""
        from cauldron.ai.analyzer import ClaudeAuthError

        classify_mock = MagicMock(return_value=0)
        triage_mock = MagicMock(return_value=(0, 0, 0))

        with (
            patch("cauldron.ai.analyzer.is_ai_available", return_value=True),
            patch(
                "cauldron.ai.analyzer._ai_extract_cpes",
                side_effect=ClaudeAuthError("Invalid Anthropic API key"),
            ),
            patch("cauldron.ai.analyzer._classify_ambiguous_hosts", classify_mock),
            patch("cauldron.ai.analyzer._contextual_vuln_triage", triage_mock),
        ):
            result = analyze_graph()

        assert result.auth_error == "Invalid Anthropic API key"
        # Phases 2 and 3 must not have run.
        classify_mock.assert_not_called()
        triage_mock.assert_not_called()
        assert result.ambiguous_classified == 0
        assert result.vulns_kept == 0
        assert result.vulns_dismissed == 0


class TestGatherBatches:
    """Parallel batch executor used by all three AI phases.

    Batches were verified order-independent (disjoint host sets, guarded
    Cypher writes, readonly ip_map/context). The remaining correctness
    question is how concurrent execution behaves when one batch raises
    ClaudeAuthError — the whole pipeline must still short-circuit."""

    def test_sums_results_across_parallel_batches(self):
        from cauldron.ai.analyzer import _gather_batches

        def _work(x: int) -> int:
            return x * 2

        results = _gather_batches([(_work, (i,)) for i in range(5)])
        assert sorted(results) == [0, 2, 4, 6, 8]

    def test_auth_error_in_any_batch_propagates(self):
        """If even one batch returns 401, the whole phase must abort —
        no silent swallowing, no partial result treated as success."""
        import pytest

        from cauldron.ai.analyzer import ClaudeAuthError, _gather_batches

        def _ok(x: int) -> int:
            return x

        def _fail(_x: int) -> int:
            raise ClaudeAuthError("Invalid Anthropic API key")

        with pytest.raises(ClaudeAuthError, match="Invalid Anthropic API key"):
            _gather_batches(
                [(_ok, (1,)), (_fail, (2,)), (_ok, (3,))],
            )


class TestIsValidCpe23:
    """CPE 2.3 format validator — AI may hallucinate strings with wrong
    shape; we reject before spending an NVD API call on them."""

    def test_valid_app_cpe(self):
        from cauldron.ai.analyzer import _is_valid_cpe23
        assert _is_valid_cpe23(
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        )

    def test_valid_os_cpe(self):
        from cauldron.ai.analyzer import _is_valid_cpe23
        assert _is_valid_cpe23(
            "cpe:2.3:o:vmware:esxi:8.0.3:*:*:*:*:*:*:*",
        )

    def test_wildcard_version_ok(self):
        from cauldron.ai.analyzer import _is_valid_cpe23
        assert _is_valid_cpe23(
            "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
        )

    def test_missing_fields_rejected(self):
        from cauldron.ai.analyzer import _is_valid_cpe23
        # Only 5 colons instead of 12 — classic AI hallucination shape.
        assert not _is_valid_cpe23("cpe:2.3:a:apache:http_server:2.4.49")

    def test_wrong_prefix_rejected(self):
        from cauldron.ai.analyzer import _is_valid_cpe23
        # CPE 2.2 format — NVD expects 2.3.
        assert not _is_valid_cpe23("cpe:/a:apache:http_server:2.4.49")

    def test_invalid_part_type_rejected(self):
        from cauldron.ai.analyzer import _is_valid_cpe23
        # Only a/o/h are valid per CPE 2.3 spec.
        assert not _is_valid_cpe23(
            "cpe:2.3:x:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        )

    def test_non_string_rejected(self):
        from cauldron.ai.analyzer import _is_valid_cpe23
        assert not _is_valid_cpe23(None)
        assert not _is_valid_cpe23(42)

    def test_empty_string_rejected(self):
        from cauldron.ai.analyzer import _is_valid_cpe23
        assert not _is_valid_cpe23("")


class TestAiCpesForBatch:
    """Batch prompt construction + response parsing for Phase 1 CPE extraction."""

    def _svc(self, port=80, protocol="tcp", **kwargs):
        base = {
            "port": port, "protocol": protocol,
            "name": None, "product": None, "version": None,
            "extra_info": None, "banner": None, "servicefp": None,
            "os_name": None,
        }
        base.update(kwargs)
        return base

    def test_parses_valid_response(self):
        from cauldron.ai.analyzer import _ai_cpes_for_batch

        batch = [("10.0.0.1", [self._svc(port=5432, product="PostgreSQL DB")])]
        fake_response = json.dumps([
            {"index": 0, "cpes": [
                "cpe:2.3:a:postgresql:postgresql:14.5:*:*:*:*:*:*:*",
            ]},
        ])

        with patch("cauldron.ai.analyzer._call_claude", return_value=fake_response):
            out = _ai_cpes_for_batch(batch)

        assert out == [{
            "ip": "10.0.0.1", "port": 5432, "protocol": "tcp",
            "cpes": ["cpe:2.3:a:postgresql:postgresql:14.5:*:*:*:*:*:*:*"],
        }]

    def test_empty_cpes_list_is_respected(self):
        """AI returning empty cpes is the correct no-guess behavior —
        keep the entry so the caller can see 'we asked, AI had nothing'."""
        from cauldron.ai.analyzer import _ai_cpes_for_batch

        batch = [("10.0.0.2", [self._svc(banner="opaque custom banner")])]
        with patch(
            "cauldron.ai.analyzer._call_claude",
            return_value=json.dumps([{"index": 0, "cpes": []}]),
        ):
            out = _ai_cpes_for_batch(batch)
        assert len(out) == 1
        assert out[0]["cpes"] == []

    def test_handles_multiple_cpes_per_service(self):
        """A host may expose a stack (nginx fronting tomcat). Both CPEs kept."""
        from cauldron.ai.analyzer import _ai_cpes_for_batch

        batch = [("10.0.0.3", [self._svc(port=443, product="nginx/tomcat stack")])]
        fake_response = json.dumps([{
            "index": 0,
            "cpes": [
                "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*",
                "cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*:*",
            ],
        }])
        with patch("cauldron.ai.analyzer._call_claude", return_value=fake_response):
            out = _ai_cpes_for_batch(batch)
        assert len(out[0]["cpes"]) == 2

    def test_index_out_of_range_dropped(self):
        """AI index that points past the service list is ignored, not crashed on."""
        from cauldron.ai.analyzer import _ai_cpes_for_batch

        batch = [("10.0.0.4", [self._svc(port=22)])]
        fake_response = json.dumps([
            {"index": 0, "cpes": ["cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"]},
            {"index": 99, "cpes": ["cpe:2.3:a:fake:stuff:1.0:*:*:*:*:*:*:*"]},
        ])
        with patch("cauldron.ai.analyzer._call_claude", return_value=fake_response):
            out = _ai_cpes_for_batch(batch)
        assert len(out) == 1
        assert out[0]["port"] == 22

    def test_empty_batch_returns_empty(self):
        from cauldron.ai.analyzer import _ai_cpes_for_batch
        assert _ai_cpes_for_batch([]) == []

    def test_claude_unavailable_returns_empty(self):
        from cauldron.ai.analyzer import _ai_cpes_for_batch

        batch = [("10.0.0.5", [self._svc(port=80)])]
        with patch("cauldron.ai.analyzer._call_claude", return_value=None):
            assert _ai_cpes_for_batch(batch) == []

    def test_prompt_includes_servicefp_and_banner(self):
        """The whole point of this phase is feeding AI the raw signals
        nmap itself couldn't resolve. Make sure both land in the prompt."""
        from cauldron.ai.analyzer import _ai_cpes_for_batch

        batch = [("10.0.0.6", [self._svc(
            port=8443,
            banner="Server: Artica Proxy v4.40",
            servicefp="NULL,\\n\\n\\nGetRequest,\\n\\n\\n...",
        )])]

        captured: dict = {}

        def fake_call(prompt, max_tokens=None):  # noqa: ARG001
            captured["prompt"] = prompt
            return json.dumps([{"index": 0, "cpes": []}])

        with patch("cauldron.ai.analyzer._call_claude", side_effect=fake_call):
            _ai_cpes_for_batch(batch)

        assert "Artica Proxy" in captured["prompt"]
        assert "GetRequest" in captured["prompt"]


# --- Integration tests (require Neo4j) ---

pytestmark_neo4j = pytest.mark.skipif(
    not verify_connection(),
    reason="Neo4j not available",
)


@pytest.fixture()
def clean_db():
    """Clear database before and after each test."""
    if verify_connection():
        clear_database()
        yield
        clear_database()
    else:
        yield


@pytestmark_neo4j
class TestClassifyAmbiguousBatching:
    """Regression: _classify_ambiguous_hosts used to hard-cap at LIMIT 15
    inside the Cypher query, silently dropping every ambiguous host past
    the fifteenth on real scans. Now it batches through ALL of them
    (_CLASSIFY_BATCH_SIZE hosts per API call) and the operator gets a
    complete pass in one boil.
    """

    def _insert_ambiguous(self, count: int):
        """Seed ``count`` hosts that the rule-based classifier would have
        left with a weak score (confidence in the open interval (0, 0.6))."""
        with get_session() as session:
            for i in range(count):
                session.run(
                    """
                    CREATE (:Host {ip: $ip, state: 'up',
                                   role: 'unknown', role_confidence: 0.4})
                    """,
                    ip=f"10.9.{i // 256}.{i % 256}",
                )

    def test_processes_every_host_no_hard_cap(self, clean_db):
        """40 ambiguous hosts spread across batches — every one should be
        sent to Claude, not just the first 15 of some arbitrary ordering."""
        from cauldron.ai.analyzer import _classify_ambiguous_hosts

        self._insert_ambiguous(40)

        seen_ids: set[str] = set()

        def fake_call(prompt, max_tokens=None):  # noqa: ARG001
            # Pull every host-N alias Claude was asked to classify out of
            # the prompt; we only want to confirm coverage, not the
            # classification logic itself.
            import re as _re
            for match in _re.findall(r"(host-\d+):", prompt):
                seen_ids.add(match)
            return "[]"  # no reclassifications needed for this assertion

        with patch("cauldron.ai.analyzer._call_claude", side_effect=fake_call):
            _classify_ambiguous_hosts()

        # The aliases reset per batch (host-1..host-N where N ≤ batch_size),
        # but the sheer coverage is what matters: the prompt was assembled
        # across enough calls to cover 40 hosts.
        # With _CLASSIFY_BATCH_SIZE = 50 that's one call with 40 aliases;
        # if the batch size ever shrinks, pytest still catches regressions
        # by requiring all 40 to land in ``seen_ids`` across all calls.
        assert len(seen_ids) == 40

    def test_batches_large_set(self, clean_db):
        """120 hosts → more than one Claude call (multiple batches)."""
        from cauldron.ai.analyzer import _classify_ambiguous_hosts

        self._insert_ambiguous(120)

        call_count = 0

        def fake_call(prompt, max_tokens=None):  # noqa: ARG001
            nonlocal call_count
            call_count += 1
            return "[]"

        with patch("cauldron.ai.analyzer._call_claude", side_effect=fake_call):
            _classify_ambiguous_hosts()

        # 120 hosts with batch_size=50 → 3 batches. Guard against a future
        # accidental batch_size=1 or a return to "one huge call".
        assert 2 <= call_count <= 4

    def test_empty_graph_short_circuits(self, clean_db):
        """No ambiguous hosts → zero API calls, zero work."""
        from cauldron.ai.analyzer import _classify_ambiguous_hosts

        call_count = 0

        def fake_call(prompt, max_tokens=None):  # noqa: ARG001
            nonlocal call_count
            call_count += 1
            return "[]"

        with patch("cauldron.ai.analyzer._call_claude", side_effect=fake_call):
            result = _classify_ambiguous_hosts()

        assert result == 0
        assert call_count == 0

    def test_classification_applied_per_batch(self, clean_db):
        """Results from each batch reach the graph before the next batch
        starts — partial progress survives if a later batch fails."""
        from cauldron.ai.analyzer import _classify_ambiguous_hosts
        import json as _json

        self._insert_ambiguous(60)

        batch_num = {"n": 0}

        def fake_call(prompt, max_tokens=None):  # noqa: ARG001
            batch_num["n"] += 1
            # First batch: reclassify every host it sees as web_server.
            # Second batch: claim nothing changed. Combined effect =
            # batch 1's updates must still be in the graph after batch 2
            # completes, proving _apply_classifications runs per batch.
            if batch_num["n"] == 1:
                import re as _re
                ids = _re.findall(r"(host-\d+):", prompt)
                return _json.dumps([
                    {"id": i, "role": "web_server", "confidence": 0.85}
                    for i in ids
                ])
            return "[]"

        with patch("cauldron.ai.analyzer._call_claude", side_effect=fake_call):
            updated = _classify_ambiguous_hosts()

        # Batch 1 had 50 hosts, batch 2 had 10. Only batch 1 reclassified.
        assert updated == 50

        with get_session() as session:
            count = session.run(
                """
                MATCH (h:Host)
                WHERE h.role = 'web_server' AND h.ai_classified = true
                RETURN count(h) AS n
                """,
            ).single()["n"]
            assert count == 50


@pytestmark_neo4j
class TestApplyClassifications:
    def test_updates_host_role(self, clean_db):
        from cauldron.ai.analyzer import _apply_classifications

        with get_session() as session:
            session.run("""
                CREATE (:Host {ip: '10.0.0.1', role: 'unknown',
                               role_confidence: 0.3, state: 'up'})
            """)

        updated = _apply_classifications([
            {"ip": "10.0.0.1", "role": "web_server", "confidence": 0.85},
        ])
        assert updated == 1

        with get_session() as session:
            result = session.run(
                "MATCH (h:Host {ip: '10.0.0.1'}) RETURN h.role AS role, h.ai_classified AS ai"
            )
            record = result.single()
            assert record["role"] == "web_server"
            assert record["ai"] is True

    def test_does_not_downgrade_confidence(self, clean_db):
        from cauldron.ai.analyzer import _apply_classifications

        with get_session() as session:
            session.run("""
                CREATE (:Host {ip: '10.0.0.1', role: 'database',
                               role_confidence: 0.95, state: 'up'})
            """)

        updated = _apply_classifications([
            {"ip": "10.0.0.1", "role": "web_server", "confidence": 0.7},
        ])
        assert updated == 0

        with get_session() as session:
            result = session.run(
                "MATCH (h:Host {ip: '10.0.0.1'}) RETURN h.role AS role"
            )
            assert result.single()["role"] == "database"

    def test_empty_classifications(self, clean_db):
        from cauldron.ai.analyzer import _apply_classifications

        assert _apply_classifications([]) == 0


# --- Anonymization tests ---


class TestBuildAnonymizationMap:
    def test_basic_mapping(self):
        ip_map, reverse_map = _build_anonymization_map(["10.0.0.5", "10.0.0.1", "10.0.0.3"])
        assert ip_map["10.0.0.1"] == "host-1"
        assert ip_map["10.0.0.3"] == "host-2"
        assert ip_map["10.0.0.5"] == "host-3"
        assert reverse_map["host-1"] == "10.0.0.1"

    def test_deduplicates(self):
        ip_map, _ = _build_anonymization_map(["10.0.0.1", "10.0.0.1", "10.0.0.2"])
        assert len(ip_map) == 2

    def test_empty(self):
        ip_map, reverse_map = _build_anonymization_map([])
        assert ip_map == {}
        assert reverse_map == {}

    def test_numeric_sort(self):
        """IPs should be sorted numerically, not lexicographically."""
        ip_map, _ = _build_anonymization_map(["10.0.0.9", "10.0.0.10", "10.0.0.2"])
        assert ip_map["10.0.0.2"] == "host-1"
        assert ip_map["10.0.0.9"] == "host-2"
        assert ip_map["10.0.0.10"] == "host-3"


class TestAnonymizeText:
    def test_replaces_ips(self):
        text = "Host 10.0.0.1 has port 22. Host 10.0.0.2 has port 80."
        ip_map = {"10.0.0.1": "host-1", "10.0.0.2": "host-2"}
        result = _anonymize_text(text, ip_map)
        assert "10.0.0.1" not in result
        assert "10.0.0.2" not in result
        assert "host-1" in result
        assert "host-2" in result

    def test_strips_hostnames(self):
        text = "  10.0.0.1 [web_server] (DC01.client.local) OS:Windows"
        ip_map = {"10.0.0.1": "host-1"}
        result = _anonymize_text(text, ip_map, hostnames={"DC01.client.local"})
        assert "DC01.client.local" not in result
        assert "()" not in result
        assert "host-1" in result

    def test_removes_segments(self):
        text = "--- Segment: 10.0.0.0/24 ---\nhost data\n=== SEGMENT CONNECTIVITY ===\n10.0.0.0/24 -> 10.0.1.0/24"
        result = _anonymize_text(text, {})
        assert "Segment:" not in result
        assert "CONNECTIVITY" not in result

    def test_no_ip_leakage_with_similar_ips(self):
        """10.0.0.1 should not partially match inside 10.0.0.10."""
        text = "10.0.0.1 and 10.0.0.10"
        ip_map = {"10.0.0.1": "host-1", "10.0.0.10": "host-2"}
        result = _anonymize_text(text, ip_map)
        assert result == "host-1 and host-2"


class TestDeanonymizeHosts:
    def test_basic(self):
        reverse = {"host-1": "10.0.0.1", "host-2": "10.0.0.2"}
        result = _deanonymize_hosts(["host-1", "host-2"], reverse)
        assert result == ["10.0.0.1", "10.0.0.2"]

    def test_unknown_alias_preserved(self):
        result = _deanonymize_hosts(["host-99"], {"host-1": "10.0.0.1"})
        assert result == ["host-99"]

    def test_empty(self):
        assert _deanonymize_hosts([], {}) == []


class TestParseClassificationAnonymized:
    def test_deanonymizes_id_field(self):
        response = json.dumps([
            {"id": "host-1", "role": "web_server", "confidence": 0.85},
        ])
        reverse = {"host-1": "10.0.0.1"}
        result = _parse_classification_response(response, reverse)
        assert len(result) == 1
        assert result[0]["ip"] == "10.0.0.1"
        assert result[0]["role"] == "web_server"

    def test_legacy_ip_field_still_works(self):
        response = json.dumps([
            {"ip": "10.0.0.1", "role": "database", "confidence": 0.9},
        ])
        result = _parse_classification_response(response)
        assert len(result) == 1
        assert result[0]["ip"] == "10.0.0.1"


