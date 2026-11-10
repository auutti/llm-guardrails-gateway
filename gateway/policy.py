"""Configurable content policy.

Topics are defined in config/policy.yaml as named groups of regex
patterns with an action (block or flag). The same check runs on user
input and on model output, so a policy violation is caught in both
directions.
"""

from __future__ import annotations

import re

from .config import PolicyTopic
from .injection import normalize
from .models import GuardResult, Verdict

_ACTION_TO_VERDICT = {
    "block": Verdict.BLOCK,
    "flag": Verdict.FLAG,
}


def check(text: str, topics: list[PolicyTopic]) -> GuardResult:
    """Match the normalized text against every topic pattern.

    The verdict is the strongest action among matched topics.
    """
    normalized, _ = normalize(text)
    matched_topics: list[str] = []
    verdict = Verdict.PASS
    for topic in topics:
        for pattern in topic.patterns:
            if re.search(pattern, normalized):
                matched_topics.append(f"policy.{topic.name}")
                topic_verdict = _ACTION_TO_VERDICT[topic.action]
                if topic_verdict == Verdict.BLOCK:
                    verdict = Verdict.BLOCK
                elif verdict != Verdict.BLOCK:
                    verdict = Verdict.FLAG
                break  # one match per topic is enough
    return GuardResult(
        guard="policy",
        verdict=verdict,
        score=1.0 if matched_topics else 0.0,
        reasons=sorted(set(matched_topics)),
    )
