"""Prompt-injection detection.

Approach: normalize the text first (so trivial obfuscation like
zero-width characters or Unicode homoglyph tricks doesn't help the
attacker), then match a set of weighted signals. The final score is the
capped sum of matched weights; thresholds decide PASS / FLAG / BLOCK.

This is a heuristic engine, not a classifier. It is transparent (every
verdict lists the exact signals that fired), has microsecond latency and
no model dependency. Its known limits are documented in
docs/EXPLAINED.md.
"""

from __future__ import annotations

import re
import unicodedata

from .config import InjectionConfig
from .models import GuardResult, Verdict

# Invisible characters commonly used to smuggle instructions past
# filters. Their mere presence is suspicious in ordinary user input.
_ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u200e\u200f\u2060\ufeff]")


def normalize(text: str) -> tuple[str, bool]:
    """Return (normalized_text, had_invisible_chars).

    Steps: NFKC unicode normalization -> strip zero-width characters ->
    lowercase -> collapse whitespace.
    """
    normalized = unicodedata.normalize("NFKC", text)
    had_invisible = bool(_ZERO_WIDTH.search(normalized))
    normalized = _ZERO_WIDTH.sub("", normalized)
    normalized = normalized.lower()
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized, had_invisible


# All patterns are written to run in linear time on hostile input
# (bounded repetitions, anchored runs); tests/test_performance.py guards
# against regressions.
#
# Signal list: (id, compiled regex, weight). Weights reflect how strongly
# a signal correlates with a real attack; several weak signals together
# can still cross the block threshold.
SIGNALS: list[tuple[str, re.Pattern, float]] = [
    (
        "inj.ignore_instructions",
        re.compile(
            r"(ignore|disregard|forget)\s+(all\s+|any\s+|the\s+|your\s+)?"
            r"(previous|prior|above|earlier|original|initial)?\s*"
            r"(instructions|rules|prompts|guidelines|directions)"
        ),
        0.6,
    ),
    (
        "inj.reveal_system",
        re.compile(
            r"(reveal|show|print|repeat|output|display|tell me|give me)"
            r".{0,40}(system prompt|initial instructions|hidden instructions"
            r"|your instructions|original prompt)"
        ),
        0.6,
    ),
    (
        "inj.override_safety",
        re.compile(
            r"(bypass|disable|turn off|remove|deactivate|ignore)\s+"
            r"(the\s+|your\s+|all\s+)?(safety|guardrails?|filters?|moderation"
            r"|restrictions|safeguards)"
        ),
        0.6,
    ),
    (
        "inj.fake_delimiters",
        re.compile(
            r"</?system>|\[/?system\]|###\s*system|<\|im_(start|end)\|>"
            r"|begin system prompt|\[inst\]"
        ),
        0.5,
    ),
    (
        "inj.jailbreak_persona",
        re.compile(
            r"\bdan\b.{0,30}(mode|jailbreak)|do anything now|developer mode"
            r"|\bjailbreak|evil\s+(assistant|ai|twin)"
        ),
        0.5,
    ),
    (
        "inj.new_system_prompt",
        re.compile(
            r"your new (system prompt|instructions|rules|persona) (is|are)"
            r"|update your system (prompt|message)"
            r"|here (is|are) your new (instructions|rules)"
        ),
        0.5,
    ),
    (
        "inj.role_override",
        re.compile(
            r"you are now [a-z]|from now on,? you (are|will|must)"
            r"|pretend (that )?you (are|have)|act as if you (are|have|were)"
        ),
        0.4,
    ),
    (
        "inj.no_rules_claim",
        re.compile(
            r"without (any )?(\w+ )?(restrictions|filters|rules|limitations"
            r"|ethics|boundaries|constraints)"
            r"|you have no (guidelines|restrictions|limits|rules)"
            r"|(no|free of) (ethical|moral) (constraints|guidelines)"
        ),
        0.4,
    ),
    (
        "inj.instruction_in_data",
        re.compile(
            r"the (above|previous) (instructions|text|rules) (are|is) "
            r"(wrong|outdated|cancelled|void)"
            r"|new instructions:|important system update:"
        ),
        0.4,
    ),
    (
        "inj.exfiltration",
        re.compile(
            r"(send|post|forward|email|transmit)\s+(this|the conversation"
            r"|everything|all (data|messages)|the (chat|history))"
            r".{0,30}(to\s+)?https?://"
            r"|!\[[^\]]{0,300}\]\(https?://"  # markdown image exfiltration
        ),
        0.4,
    ),
    (
        "inj.base64_payload",
        re.compile(
            r"(decode|execute|run|eval).{0,60}[a-z0-9+/=]{60,}"
            # Lookbehind + possessive quantifier: each long run is scanned
            # exactly once, so hostile input cannot trigger backtracking.
            r"|(?<![a-z0-9+/=])[a-z0-9+/=]{60,}+.{0,60}(decode|execute|run|eval)"
        ),
        0.4,
    ),
]

#: Signal id used when normalization found invisible characters.
ZERO_WIDTH_SIGNAL = ("inj.zero_width_obfuscation", 0.3)


def score_text(text: str) -> tuple[float, list[str]]:
    """Return (score 0..1, matched signal ids) for a raw text."""
    normalized, had_invisible = normalize(text)
    matched: list[str] = []
    total = 0.0
    for signal_id, pattern, weight in SIGNALS:
        if pattern.search(normalized):
            matched.append(signal_id)
            total += weight
    if had_invisible:
        matched.append(ZERO_WIDTH_SIGNAL[0])
        total += ZERO_WIDTH_SIGNAL[1]
    return min(1.0, total), matched


def check(text: str, cfg: InjectionConfig | None = None) -> GuardResult:
    """Guard interface: score the text and map to a verdict."""
    cfg = cfg or InjectionConfig()
    score, matched = score_text(text)
    if score >= cfg.block_threshold:
        verdict = Verdict.BLOCK
    elif score >= cfg.flag_threshold:
        verdict = Verdict.FLAG
    else:
        verdict = Verdict.PASS
    return GuardResult(
        guard="injection", verdict=verdict, score=score, reasons=matched
    )
