"""Core data structures shared by all guards.

Every guard returns a GuardResult. The pipeline combines several
GuardResults into a PipelineResult whose overall verdict is the most
severe verdict any guard produced.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    """What the gateway decided about a piece of text.

    PASS   -- nothing found, text goes through unchanged
    FLAG   -- suspicious but not certain; text goes through, but the
              event is recorded in the audit log and response headers
    REDACT -- sensitive data was found and replaced with placeholders
    BLOCK  -- the request/response is refused outright
    """

    PASS = "pass"
    FLAG = "flag"
    REDACT = "redact"
    BLOCK = "block"


#: Numeric severity used to pick the "worst" verdict across guards.
SEVERITY: dict[Verdict, int] = {
    Verdict.PASS: 0,
    Verdict.FLAG: 1,
    Verdict.REDACT: 2,
    Verdict.BLOCK: 3,
}


def max_verdict(verdicts: list[Verdict]) -> Verdict:
    """Return the most severe verdict in the list (PASS if empty)."""
    if not verdicts:
        return Verdict.PASS
    return max(verdicts, key=lambda v: SEVERITY[v])


@dataclass
class GuardResult:
    """Outcome of a single guard applied to a single text."""

    guard: str                      # e.g. "pii", "injection", "policy"
    verdict: Verdict
    score: float = 0.0              # 0..1 confidence (binary guards use 0/1)
    reasons: list[str] = field(default_factory=list)  # matched rule ids
    transformed_text: str | None = None  # redacted text if verdict == REDACT

    def to_dict(self) -> dict:
        """Compact representation for audit logs and response metadata."""
        return {
            "guard": self.guard,
            "verdict": self.verdict.value,
            "score": round(self.score, 3),
            "reasons": self.reasons,
        }


@dataclass
class PipelineResult:
    """Combined outcome of a chain of guards over one text."""

    verdict: Verdict
    results: list[GuardResult]
    text: str  # final text after any redactions

    def header_summary(self) -> str:
        """One-line summary for the X-Guardrails-* response headers.

        Example: "pii=redact;injection=pass;policy=pass"
        """
        return ";".join(f"{r.guard}={r.verdict.value}" for r in self.results)

    def all_reasons(self) -> list[str]:
        reasons: list[str] = []
        for r in self.results:
            reasons.extend(r.reasons)
        return reasons

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "results": [r.to_dict() for r in self.results],
        }
