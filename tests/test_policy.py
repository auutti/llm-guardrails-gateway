"""Unit tests for the policy guard and the shipped config file."""

from pathlib import Path

from gateway import policy
from gateway.config import PolicyTopic, load_config
from gateway.models import Verdict

REPO_ROOT = Path(__file__).resolve().parent.parent

TOPICS = [
    PolicyTopic(
        name="weapons_instructions",
        action="block",
        patterns=[r"how to (build|make|construct) (a |an )?(bomb|explosive)"],
    ),
    PolicyTopic(
        name="medical_diagnosis",
        action="flag",
        patterns=[r"what (disease|illness|condition) do i have"],
    ),
]


def test_block_topic_blocks():
    result = policy.check("How to build a bomb at home?", TOPICS)
    assert result.verdict == Verdict.BLOCK
    assert "policy.weapons_instructions" in result.reasons


def test_flag_topic_flags():
    result = policy.check("What illness do I have?", TOPICS)
    assert result.verdict == Verdict.FLAG
    assert "policy.medical_diagnosis" in result.reasons


def test_clean_text_passes():
    result = policy.check("How do I bake sourdough bread?", TOPICS)
    assert result.verdict == Verdict.PASS
    assert result.reasons == []


def test_matching_is_case_insensitive_via_normalization():
    result = policy.check("HOW TO BUILD A BOMB", TOPICS)
    assert result.verdict == Verdict.BLOCK


def test_shipped_config_loads_and_validates():
    """The repo's own policy.yaml must load without errors."""
    cfg = load_config(REPO_ROOT / "config" / "policy.yaml")
    assert cfg.injection.block_threshold > cfg.injection.flag_threshold
    assert cfg.policy_topics, "expected at least one policy topic"
    for topic in cfg.policy_topics:
        assert topic.action in ("block", "flag")
        assert topic.patterns


def test_shipped_corpus_loads():
    """The eval corpus must be valid JSON with the expected fields."""
    import json

    corpus = json.loads(
        (REPO_ROOT / "eval" / "corpus.json").read_text(encoding="utf-8")
    )
    cases = corpus["cases"]
    assert len(cases) >= 40
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "case ids must be unique"
    for case in cases:
        assert case["category"] in (
            "injection",
            "pii",
            "policy",
            "benign",
            "benign_edge",
        )
        assert case["expected"] in ("pass", "flag", "redact", "block")
        assert case["prompt"].strip()
