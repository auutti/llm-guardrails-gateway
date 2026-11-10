"""Audit logging and metrics.

Every request produces exactly one JSONL record. Privacy by design: raw
prompt/response text is NOT stored unless audit.log_content is enabled
in the config -- only SHA-256 hashes, lengths, verdicts, token usage and
timings. That keeps the audit trail useful for compliance reviews
without turning the log itself into a PII store.

Run `python -m gateway.audit <path>` to print a metrics summary of an
existing audit log.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from statistics import median, quantiles


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AuditLogger:
    """Append-only JSONL writer."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, record: dict) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def summarize(path: str | Path) -> dict:
    """Aggregate an audit log into headline metrics."""
    records: list[dict] = []
    log_path = Path(path)
    if log_path.exists():
        with log_path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    records.append(json.loads(line))

    if not records:
        return {"total_requests": 0}

    verdict_counts: dict[str, int] = {}
    outcome_counts: dict[str, int] = {}
    latencies: list[float] = []
    total_prompt_tokens = 0
    total_completion_tokens = 0
    for record in records:
        verdict = record.get("input_verdict", "unknown")
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        outcome = record.get("outcome", "unknown")
        outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1
        if isinstance(record.get("total_ms"), (int, float)):
            latencies.append(float(record["total_ms"]))
        usage = record.get("usage") or {}
        total_prompt_tokens += int(usage.get("prompt_tokens") or 0)
        total_completion_tokens += int(usage.get("completion_tokens") or 0)

    summary = {
        "total_requests": len(records),
        "input_verdicts": verdict_counts,
        "outcomes": outcome_counts,
        "blocked_rate": round(
            outcome_counts.get("blocked", 0) / len(records), 3
        ),
        "tokens": {
            "prompt": total_prompt_tokens,
            "completion": total_completion_tokens,
        },
    }
    if latencies:
        summary["latency_ms"] = {
            "p50": round(median(latencies), 1),
            "p95": round(
                quantiles(latencies, n=20)[18] if len(latencies) >= 2 else latencies[0],
                1,
            ),
            "max": round(max(latencies), 1),
        }
    return summary


if __name__ == "__main__":
    log_file = sys.argv[1] if len(sys.argv) > 1 else "logs/audit.jsonl"
    print(json.dumps(summarize(log_file), indent=2))
