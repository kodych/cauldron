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
    _parse_attack_insights,
    _parse_classification_response,
    _parse_fp_response,
    _parse_json_response,
    analyze_graph,
    is_ai_available,
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


class TestIsAiAvailable:
    def test_available_with_key(self):
        with patch("cauldron.ai.analyzer.settings") as mock_settings:
            mock_settings.anthropic_api_key = "sk-ant-test123"
            assert is_ai_available() is True

    def test_unavailable_without_key(self):
        with patch("cauldron.ai.analyzer.settings") as mock_settings:
            mock_settings.anthropic_api_key = ""
            assert is_ai_available() is False


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

    def test_auth_error(self):
        from cauldron.ai.analyzer import _call_claude

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

                result = _call_claude("test")
                assert result is None

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
            assert result.insights == []
            assert result.cves_found == 0
            assert result.insights == []


class TestApplyAiCves:
    def test_index_based_matching(self):
        from cauldron.ai.analyzer import _apply_ai_cves

        pairs = [("Apache", "2.4.49"), ("nginx", "1.14.1")]
        response = json.dumps([{
            "index": 0,
            "cves": [{
                "cve_id": "CVE-2021-41773",
                "cvss": 7.5,
                "severity": "HIGH",
                "has_exploit": True,
                "description": "Path traversal",
            }],
        }])

        with patch("cauldron.ai.analyzer.get_session") as mock_get_session:
            mock_session = MagicMock()
            mock_get_session.return_value.__enter__ = MagicMock(return_value=mock_session)
            mock_get_session.return_value.__exit__ = MagicMock(return_value=False)
            # Mock link query to return linked=1
            mock_result = MagicMock()
            mock_result.single.return_value = {"linked": 1}
            mock_session.run.return_value = mock_result

            cves, services = _apply_ai_cves(response, pairs)
            assert cves == 1
            assert services == 1

    def test_fallback_to_product_version(self):
        """When no index provided, falls back to product+version fields."""
        from cauldron.ai.analyzer import _apply_ai_cves

        response = json.dumps([{
            "product": "Apache",
            "version": "2.4.49",
            "cves": [{"cve_id": "CVE-2021-41773", "cvss": 7.5}],
        }])

        with patch("cauldron.ai.analyzer.get_session") as mock_get_session:
            mock_session = MagicMock()
            mock_get_session.return_value.__enter__ = MagicMock(return_value=mock_session)
            mock_get_session.return_value.__exit__ = MagicMock(return_value=False)
            mock_result = MagicMock()
            mock_result.single.return_value = {"linked": 1}
            mock_session.run.return_value = mock_result

            cves, services = _apply_ai_cves(response)
            assert cves == 1

    def test_skips_invalid_cve_ids(self):
        from cauldron.ai.analyzer import _apply_ai_cves

        response = json.dumps([{
            "index": 0,
            "cves": [{"cve_id": "NOT-A-CVE", "cvss": 5.0}],
        }])

        with patch("cauldron.ai.analyzer.get_session") as mock_get_session:
            mock_session = MagicMock()
            mock_get_session.return_value.__enter__ = MagicMock(return_value=mock_session)
            mock_get_session.return_value.__exit__ = MagicMock(return_value=False)

            cves, services = _apply_ai_cves(response, [("Apache", "2.4.49")])
            assert cves == 0
            assert services == 0

    def test_handles_invalid_json(self):
        from cauldron.ai.analyzer import _apply_ai_cves

        cves, services = _apply_ai_cves("not json")
        assert cves == 0
        assert services == 0


class TestParseAttackInsights:
    def test_valid_insight(self):
        from cauldron.ai.analyzer import _parse_attack_insights

        response = json.dumps([{
            "type": "attack_chain",
            "title": "Printer pivot to DC",
            "hosts": ["10.0.0.5", "10.0.1.10"],
            "priority": 1,
            "confidence": 0.85,
            "details": "SNMP to AD exploitation",
        }])

        insights = _parse_attack_insights(response)
        assert len(insights) == 1
        assert insights[0].title == "Printer pivot to DC"
        assert insights[0].hosts == ["10.0.0.5", "10.0.1.10"]
        assert insights[0].priority == 1

    def test_filters_low_confidence(self):
        from cauldron.ai.analyzer import _parse_attack_insights

        response = json.dumps([{
            "type": "attack_chain",
            "title": "Bad chain",
            "hosts": ["10.0.0.1", "10.0.0.2"],
            "priority": 1,
            "confidence": 0.3,
        }])

        insights = _parse_attack_insights(response)
        assert len(insights) == 0

    def test_handles_invalid_json(self):
        from cauldron.ai.analyzer import _parse_attack_insights

        insights = _parse_attack_insights("broken")
        assert insights == []

    def test_sorts_by_priority(self):
        from cauldron.ai.analyzer import _parse_attack_insights

        response = json.dumps([
            {"type": "attack_chain", "title": "Low", "hosts": ["10.0.0.1", "10.0.0.2"],
             "priority": 4, "confidence": 0.9},
            {"type": "attack_chain", "title": "High", "hosts": ["10.0.0.3", "10.0.0.4"],
             "priority": 1, "confidence": 0.9},
        ])

        insights = _parse_attack_insights(response)
        assert len(insights) == 2
        assert insights[0].title == "High"
        assert insights[1].title == "Low"

    def test_accepts_path_key_for_backwards_compat(self):
        """AI might still return 'path' key instead of 'hosts'."""
        from cauldron.ai.analyzer import _parse_attack_insights

        response = json.dumps([{
            "type": "attack_chain",
            "title": "Chain via path key",
            "path": ["10.0.0.1", "10.0.0.2"],
            "priority": 2,
            "confidence": 0.8,
        }])

        insights = _parse_attack_insights(response)
        assert len(insights) == 1
        assert insights[0].hosts == ["10.0.0.1", "10.0.0.2"]


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


class TestParseAttackInsightsAnonymized:
    def test_deanonymizes_hosts(self):
        response = json.dumps([{
            "type": "attack_chain",
            "title": "DC to DB lateral movement",
            "hosts": ["host-1", "host-2"],
            "priority": 1,
            "confidence": 0.9,
            "details": "Exploit DC then pivot to DB",
        }])
        reverse = {"host-1": "10.0.0.1", "host-2": "10.0.0.2"}
        result = _parse_attack_insights(response, reverse)
        assert len(result) == 1
        assert result[0].hosts == ["10.0.0.1", "10.0.0.2"]

    def test_without_reverse_map(self):
        response = json.dumps([{
            "type": "attack_chain",
            "title": "Test",
            "hosts": ["host-1"],
            "priority": 2,
            "confidence": 0.8,
            "details": "test",
        }])
        result = _parse_attack_insights(response)
        assert result[0].hosts == ["host-1"]


class TestParseFpResponse:
    def test_valid_response(self):
        response = json.dumps([{
            "id": "host-1",
            "false_positives": [
                {"cve_id": "CVE-2012-4791", "port": 3875, "reason": "DoS only, CVSS 3.5"},
            ],
        }])
        reverse = {"host-1": "10.0.0.1"}
        result = _parse_fp_response(response, reverse)
        assert len(result) == 1
        assert result[0]["ip"] == "10.0.0.1"
        assert result[0]["cve_id"] == "CVE-2012-4791"
        assert result[0]["port"] == 3875

    def test_filters_invalid_cve_ids(self):
        response = json.dumps([{
            "id": "host-1",
            "false_positives": [
                {"cve_id": "NOT-A-CVE", "port": 22, "reason": "bad"},
                {"cve_id": "CVE-2021-44228", "port": 8080, "reason": "not applicable"},
            ],
        }])
        result = _parse_fp_response(response, {"host-1": "10.0.0.1"})
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2021-44228"

    def test_accepts_cauldron_ids(self):
        response = json.dumps([{
            "id": "host-1",
            "false_positives": [
                {"cve_id": "CAULDRON-271", "port": 5985, "reason": "WinRM not exploitable"},
            ],
        }])
        result = _parse_fp_response(response, {"host-1": "10.0.0.1"})
        assert len(result) == 1

    def test_empty_response(self):
        assert _parse_fp_response("[]", {}) == []

    def test_invalid_json(self):
        assert _parse_fp_response("not json", {}) == []

    def test_missing_port_skipped(self):
        response = json.dumps([{
            "id": "host-1",
            "false_positives": [
                {"cve_id": "CVE-2021-44228", "reason": "no port"},
            ],
        }])
        result = _parse_fp_response(response, {"host-1": "10.0.0.1"})
        assert len(result) == 0
