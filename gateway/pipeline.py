"""Guard orchestration.

Input chain:  pii -> injection -> policy
Output chain: output_pii -> output policy -> (optional) json schema

The overall verdict is the most severe single verdict. A BLOCK on input
short-circuits the request before it ever reaches the upstream model --
blocked attacks cost zero tokens.
"""

from __future__ import annotations

from . import injection, output_guards, pii, policy
from .config import Config
from .models import GuardResult, PipelineResult, Verdict, max_verdict


def run_input_guards(text: str, cfg: Config) -> PipelineResult:
    """Apply all input guards to one text (typically a user message)."""
    results: list[GuardResult] = []
    current_text = text

    pii_result = pii.check(current_text, cfg.pii)
    results.append(pii_result)
    if pii_result.verdict == Verdict.REDACT and pii_result.transformed_text:
        current_text = pii_result.transformed_text

    # Injection and policy run on the redacted text: redaction never
    # hides an attack because placeholders only replace PII spans.
    results.append(injection.check(current_text, cfg.injection))
    results.append(policy.check(current_text, cfg.policy_topics))

    verdict = max_verdict([r.verdict for r in results])
    return PipelineResult(verdict=verdict, results=results, text=current_text)


def run_output_guards(
    text: str, cfg: Config, json_schema: dict | None = None
) -> PipelineResult:
    """Apply all output guards to the model's response text."""
    results: list[GuardResult] = []
    current_text = text

    if cfg.output.pii_leak_check:
        leak_result = output_guards.check_pii_leak(current_text, cfg)
        results.append(leak_result)
        if leak_result.verdict == Verdict.REDACT and leak_result.transformed_text:
            current_text = leak_result.transformed_text

    if cfg.output.policy_check:
        policy_result = policy.check(current_text, cfg.policy_topics)
        # Rename so audit logs distinguish input vs output policy hits.
        policy_result.guard = "output_policy"
        results.append(policy_result)

    if json_schema is not None:
        results.append(output_guards.check_json(current_text, json_schema, cfg))

    verdict = max_verdict([r.verdict for r in results])
    return PipelineResult(verdict=verdict, results=results, text=current_text)
