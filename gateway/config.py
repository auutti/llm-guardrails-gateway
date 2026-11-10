"""Configuration loading.

Reads config/policy.yaml into typed dataclasses with sane defaults, so
the rest of the code never touches raw dictionaries. The upstream URL
can be overridden with the UPSTREAM_BASE_URL environment variable,
which is how the CI demo points the gateway at a local Ollama server.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "policy.yaml"


@dataclass
class UpstreamConfig:
    base_url: str = "http://127.0.0.1:11434/v1"
    timeout_seconds: float = 120.0


@dataclass
class PiiConfig:
    enabled: dict[str, bool] = field(
        default_factory=lambda: {
            "email": True,
            "phone": True,
            "iban": True,
            "credit_card": True,
            "address": True,
        }
    )


@dataclass
class InjectionConfig:
    block_threshold: float = 0.7
    flag_threshold: float = 0.4


@dataclass
class PolicyTopic:
    name: str
    action: str  # "block" or "flag"
    patterns: list[str]


@dataclass
class OutputConfig:
    pii_leak_check: bool = True
    policy_check: bool = True
    json_validation_action: str = "flag"  # "flag" or "block"


@dataclass
class AuditConfig:
    path: str = "logs/audit.jsonl"
    log_content: bool = False


@dataclass
class Config:
    upstream: UpstreamConfig = field(default_factory=UpstreamConfig)
    pii: PiiConfig = field(default_factory=PiiConfig)
    injection: InjectionConfig = field(default_factory=InjectionConfig)
    policy_topics: list[PolicyTopic] = field(default_factory=list)
    output: OutputConfig = field(default_factory=OutputConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)


def load_config(path: str | Path | None = None) -> Config:
    """Load the YAML config file and apply environment overrides.

    Resolution order for the file path:
      1. explicit argument
      2. GUARDRAILS_CONFIG environment variable
      3. config/policy.yaml next to the package
    """
    if path is None:
        path = os.environ.get("GUARDRAILS_CONFIG", DEFAULT_CONFIG_PATH)
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}

    upstream_raw = raw.get("upstream", {}) or {}
    upstream = UpstreamConfig(
        base_url=upstream_raw.get("base_url", UpstreamConfig.base_url),
        timeout_seconds=float(
            upstream_raw.get("timeout_seconds", UpstreamConfig.timeout_seconds)
        ),
    )
    # Environment variable wins (used by CI).
    env_url = os.environ.get("UPSTREAM_BASE_URL")
    if env_url:
        upstream.base_url = env_url

    pii_raw = raw.get("pii", {}) or {}
    pii = PiiConfig()
    for name, flag in (pii_raw.get("enabled", {}) or {}).items():
        pii.enabled[name] = bool(flag)

    injection_raw = raw.get("injection", {}) or {}
    injection = InjectionConfig(
        block_threshold=float(
            injection_raw.get("block_threshold", InjectionConfig.block_threshold)
        ),
        flag_threshold=float(
            injection_raw.get("flag_threshold", InjectionConfig.flag_threshold)
        ),
    )

    topics: list[PolicyTopic] = []
    policy_raw = raw.get("policy", {}) or {}
    for topic in policy_raw.get("topics", []) or []:
        action = str(topic.get("action", "flag")).lower()
        if action not in ("block", "flag"):
            raise ValueError(
                f"policy topic '{topic.get('name')}': action must be 'block' or 'flag'"
            )
        topics.append(
            PolicyTopic(
                name=str(topic["name"]),
                action=action,
                patterns=[str(p) for p in topic.get("patterns", [])],
            )
        )

    output_raw = raw.get("output", {}) or {}
    json_action = str(
        output_raw.get("json_validation_action", OutputConfig.json_validation_action)
    ).lower()
    if json_action not in ("block", "flag"):
        raise ValueError("output.json_validation_action must be 'block' or 'flag'")
    output = OutputConfig(
        pii_leak_check=bool(output_raw.get("pii_leak_check", True)),
        policy_check=bool(output_raw.get("policy_check", True)),
        json_validation_action=json_action,
    )

    audit_raw = raw.get("audit", {}) or {}
    audit = AuditConfig(
        path=str(audit_raw.get("path", AuditConfig.path)),
        log_content=bool(audit_raw.get("log_content", False)),
    )

    return Config(
        upstream=upstream,
        pii=pii,
        injection=injection,
        policy_topics=topics,
        output=output,
        audit=audit,
    )
