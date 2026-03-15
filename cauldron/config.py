"""Cauldron configuration."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings, loaded from environment variables."""

    # Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "cauldron"

    # AI (Anthropic Claude)
    anthropic_api_key: str = ""
    ai_model: str = "claude-sonnet-4-20250514"

    # NVD API (optional, for higher rate limits)
    nvd_api_key: str = ""

    # Network segmentation (default /24, adjust for non-standard subnets)
    segment_prefix_len: int = 24

    model_config = {"env_prefix": "CAULDRON_", "env_file": ".env"}


settings = Settings()
