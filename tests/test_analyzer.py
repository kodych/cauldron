"""Tests for AI analyzer module."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from cauldron.ai.analyzer import (
    AIInsight,
    AnalysisResult,
    _build_chain_discovery_prompt,
    _build_classification_prompt,
    _parse_chain_response,
    _parse_classification_response,
    analyze_graph,
    is_ai_available,
    store_insights,
)
from cauldron.graph.connection import clear_database, get_session, verify_connection

# --- Unit tests (no Neo4j needed) ---


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


class TestParseChainResponse:
    def test_valid_chain(self):
        response = json.dumps([{
            "type": "attack_chain",
            "title": "Printer pivot to DC",
            "details": "Exploit printer, pivot to DC via shared segment",
            "hosts": ["10.0.0.5", "10.0.1.10"],
            "cves": ["CVE-2021-1234"],
            "priority": 1,
            "confidence": 0.85,
        }])
        result = _parse_chain_response(response)
        assert len(result) == 1
        assert result[0].title == "Printer pivot to DC"
        assert result[0].priority == 1
        assert "10.0.0.5" in result[0].hosts

    def test_filters_low_confidence(self):
        response = json.dumps([
            {"type": "attack_chain", "title": "Good", "details": "x",
             "priority": 1, "confidence": 0.8},
            {"type": "attack_chain", "title": "Bad", "details": "x",
             "priority": 2, "confidence": 0.3},
        ])
        result = _parse_chain_response(response)
        assert len(result) == 1
        assert result[0].title == "Good"

    def test_sorts_by_priority(self):
        response = json.dumps([
            {"type": "attack_chain", "title": "Low prio", "details": "x",
             "priority": 4, "confidence": 0.9},
            {"type": "attack_chain", "title": "High prio", "details": "x",
             "priority": 1, "confidence": 0.9},
            {"type": "correlation", "title": "Mid prio", "details": "x",
             "priority": 2, "confidence": 0.8},
        ])
        result = _parse_chain_response(response)
        assert len(result) == 3
        assert result[0].title == "High prio"
        assert result[1].title == "Mid prio"
        assert result[2].title == "Low prio"

    def test_handles_markdown_fences(self):
        response = "```json\n" + json.dumps([{
            "type": "chokepoint", "title": "Gateway host", "details": "x",
            "hosts": ["10.0.0.1"], "priority": 2, "confidence": 0.7,
        }]) + "\n```"
        result = _parse_chain_response(response)
        assert len(result) == 1

    def test_handles_invalid_json(self):
        result = _parse_chain_response("broken {json")
        assert result == []

    def test_handles_empty_array(self):
        result = _parse_chain_response("[]")
        assert result == []

    def test_skips_items_without_title(self):
        response = json.dumps([
            {"type": "attack_chain", "details": "x", "priority": 1, "confidence": 0.9},
            {"type": "attack_chain", "title": "Has title", "details": "x",
             "priority": 1, "confidence": 0.9},
        ])
        result = _parse_chain_response(response)
        assert len(result) == 1


class TestBuildPrompts:
    def test_classification_prompt_includes_host_data(self):
        hosts = [{
            "ip": "10.0.0.1",
            "hostname": "web01.corp",
            "current_role": "unknown",
            "confidence": 0.3,
            "services": [
                {"port": 80, "protocol": "tcp", "name": "http",
                 "product": "Apache", "version": "2.4.49"},
            ],
        }]
        prompt = _build_classification_prompt(hosts)
        assert "10.0.0.1" in prompt
        assert "web01.corp" in prompt
        assert "Apache" in prompt
        assert "JSON array" in prompt

    def test_classification_prompt_handles_no_services(self):
        hosts = [{
            "ip": "10.0.0.2",
            "hostname": None,
            "current_role": "unknown",
            "confidence": 0.1,
            "services": [{"port": None}],
        }]
        prompt = _build_classification_prompt(hosts)
        assert "10.0.0.2" in prompt
        assert "none" in prompt

    def test_chain_prompt_includes_graph_data(self):
        subgraph = {
            "hosts": [{
                "ip": "10.0.1.10",
                "hostname": "dc01.corp",
                "role": "domain_controller",
                "confidence": 0.95,
                "segment": "10.0.1.0/24",
                "services": [
                    {"port": 389, "protocol": "tcp", "name": "ldap",
                     "product": "MS LDAP", "version": None,
                     "cve": "CVE-2021-9999", "cvss": 9.8, "has_exploit": True},
                ],
            }],
            "connectivity": [
                {"from_segment": "10.0.2.0/24", "to_segment": "10.0.1.0/24"},
            ],
            "pivots": [
                {"from_ip": "10.0.2.20", "to_ip": "10.0.1.10",
                 "method": "exploit", "difficulty": "easy"},
            ],
        }
        prompt = _build_chain_discovery_prompt(subgraph)
        assert "10.0.1.10" in prompt
        assert "dc01.corp" in prompt
        assert "domain_controller" in prompt
        assert "CVE-2021-9999" in prompt
        assert "EXPLOIT AVAILABLE" in prompt
        assert "10.0.2.0/24 -> 10.0.1.0/24" in prompt

    def test_chain_prompt_handles_empty_connectivity(self):
        subgraph = {
            "hosts": [{"ip": "10.0.0.1", "role": "unknown", "services": []}],
            "connectivity": [],
            "pivots": [],
        }
        prompt = _build_chain_discovery_prompt(subgraph)
        assert "(none found)" in prompt


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
            assert result.hosts_analyzed == 0


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


@pytestmark_neo4j
class TestStoreInsights:
    def test_stores_insight_on_host(self, clean_db):
        with get_session() as session:
            session.run("CREATE (:Host {ip: '10.0.0.1', state: 'up'})")

        insights = [AIInsight(
            insight_type="attack_chain",
            confidence=0.9,
            title="Printer pivot to DC",
            details="test",
            hosts=["10.0.0.1"],
            priority=1,
        )]
        stored = store_insights(insights)
        assert stored == 1

        with get_session() as session:
            result = session.run(
                "MATCH (h:Host {ip: '10.0.0.1'}) RETURN h.ai_insight_title AS title"
            )
            assert result.single()["title"] == "Printer pivot to DC"

    def test_empty_insights(self, clean_db):
        assert store_insights([]) == 0


@pytestmark_neo4j
class TestExtractSubgraph:
    def test_extracts_hosts_and_connectivity(self, clean_db):
        from cauldron.ai.analyzer import _extract_subgraph

        with get_session() as session:
            session.run("""
                CREATE (h:Host {ip: '10.0.0.1', hostname: 'web01', state: 'up',
                               role: 'web_server', role_confidence: 0.9})
                CREATE (seg:NetworkSegment {cidr: '10.0.0.0/24'})
                CREATE (h)-[:IN_SEGMENT]->(seg)
                CREATE (h)-[:HAS_SERVICE]->(:Service {
                    port: 80, protocol: 'tcp', name: 'http',
                    product: 'Apache', version: '2.4.49', host_ip: '10.0.0.1'
                })
            """)

        subgraph = _extract_subgraph(max_hosts=10)
        assert subgraph is not None
        assert len(subgraph["hosts"]) == 1
        assert subgraph["hosts"][0]["ip"] == "10.0.0.1"

    def test_empty_graph(self, clean_db):
        from cauldron.ai.analyzer import _extract_subgraph

        subgraph = _extract_subgraph(max_hosts=10)
        assert subgraph is None
