"""Live evaluation runner.

Sends every corpus case through a RUNNING gateway (which forwards to a
real model) and writes an honest results report: hits, misses and the
false-positive rate are all computed from this run -- nothing is
hard-coded.

Usage:
    python eval/run_eval.py --gateway http://127.0.0.1:8000 \
        --model qwen2.5:0.5b --out reports/

Exit codes: 0 = evaluation completed (even with guard misses),
            2 = infrastructure failure (gateway unreachable etc.).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median

import httpx

EXPECTED_HANDLED = {"block", "flag"}


def run_case(client: httpx.Client, gateway: str, case: dict, model: str, max_tokens: int) -> dict:
    body = {
        "model": model,
        "messages": [{"role": "user", "content": case["prompt"]}],
        "temperature": 0,
        "max_tokens": max_tokens,
        "guardrails": {"include_metadata": True},
    }
    record = {
        "id": case["id"],
        "category": case["category"],
        "expected": case["expected"],
    }
    try:
        response = client.post(
            f"{gateway}/v1/chat/completions", json=body, timeout=180
        )
    except httpx.HTTPError as exc:
        record.update(verdict="error", ok=False, error=type(exc).__name__)
        return record

    if response.status_code not in (200, 400):
        record.update(
            verdict="error", ok=False, error=f"http_{response.status_code}"
        )
        return record

    verdict = response.headers.get("X-Guardrails-Verdict", "unknown")
    latency = response.headers.get("X-Guardrails-Latency-Ms")
    record.update(
        verdict=verdict,
        http_status=response.status_code,
        latency_ms=float(latency) if latency else None,
    )

    payload = response.json()
    metadata = payload.get("guardrails") or {}
    reasons: list[str] = []
    for guard_result in (metadata.get("input") or {}).get("results", []):
        reasons.extend(guard_result.get("reasons", []))
    record["reasons"] = reasons

    ok = verdict == case["expected"]
    # For redaction cases the sensitive value must be gone from the
    # text that was forwarded to the model.
    leaked: list[str] = []
    if case.get("must_not_forward"):
        redacted_input = metadata.get("redacted_input") or ""
        leaked = [s for s in case["must_not_forward"] if s in redacted_input]
        ok = ok and not leaked
    if leaked:
        record["leaked"] = leaked
    record["ok"] = ok
    return record


def build_report(records: list[dict], model: str) -> tuple[str, dict]:
    categories = ["injection", "pii", "policy", "benign", "benign_edge"]
    by_category = {c: [r for r in records if r["category"] == c] for c in categories}

    attacks = by_category["injection"] + by_category["policy"]
    attacks_handled = [r for r in attacks if r["verdict"] in EXPECTED_HANDLED]
    pii_cases = by_category["pii"]
    pii_correct = [r for r in pii_cases if r["ok"]]
    benign = by_category["benign"] + by_category["benign_edge"]
    false_positives = [r for r in benign if r["verdict"] != "pass"]
    expected_met = [r for r in records if r["ok"]]
    errors = [r for r in records if r["verdict"] == "error"]
    latencies = [r["latency_ms"] for r in records if r.get("latency_ms")]
    # Blocked requests never reach the model, so their latency is the
    # cost of the guards alone.
    blocked_latencies = [
        r["latency_ms"]
        for r in records
        if r.get("latency_ms") and r.get("http_status") == 400
    ]

    def pct(part: int, whole: int) -> str:
        return f"{100 * part / whole:.1f}%" if whole else "n/a"

    metrics = {
        "total_cases": len(records),
        "expected_met": len(expected_met),
        "expected_met_rate": pct(len(expected_met), len(records)),
        "attack_handled_rate": pct(len(attacks_handled), len(attacks)),
        "pii_redaction_correct_rate": pct(len(pii_correct), len(pii_cases)),
        "false_positive_rate_benign": pct(len(false_positives), len(benign)),
        "infrastructure_errors": len(errors),
        "latency_ms_mean": round(mean(latencies), 1) if latencies else None,
        "latency_ms_p50": round(median(latencies), 1) if latencies else None,
        "latency_ms_max": round(max(latencies), 1) if latencies else None,
        "latency_ms_blocked_mean": round(mean(blocked_latencies), 2)
        if blocked_latencies
        else None,
    }

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    commit = os.environ.get("GITHUB_SHA", "local")[:12]
    runner = "GitHub Actions" if os.environ.get("GITHUB_ACTIONS") else "local"

    lines = [
        "# Live Demo Report - LLM Guardrails Gateway",
        "",
        f"- Generated: {generated}",
        f"- Commit: `{commit}`",
        f"- Model behind the gateway: `{model}` (served locally by Ollama)",
        f"- Runner: {runner}",
        "",
        "Every number below was measured in this run. Misses are listed",
        "openly - an evaluation that only ever reports successes is not an",
        "evaluation.",
        "",
        "**How to read these numbers:** the corpus was written together with",
        "the guard rules, so the rates show that the gateway behaves as",
        "specified end to end. They are not an estimate of how it would",
        "perform against attacks it has never seen.",
        "",
        "## Summary by category",
        "",
        "| Category | Cases | Block | Flag | Redact | Pass | Error | Expected met |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for category in categories:
        rows = by_category[category]
        counts = {
            v: sum(1 for r in rows if r["verdict"] == v)
            for v in ("block", "flag", "redact", "pass", "error")
        }
        lines.append(
            f"| {category} | {len(rows)} | {counts['block']} | {counts['flag']} "
            f"| {counts['redact']} | {counts['pass']} | {counts['error']} "
            f"| {sum(1 for r in rows if r['ok'])}/{len(rows)} |"
        )

    lines += [
        "",
        "## Headline metrics",
        "",
        f"- **Attacks handled (blocked or flagged):** {metrics['attack_handled_rate']}"
        f" ({len(attacks_handled)}/{len(attacks)})",
        f"- **PII redaction fully correct:** {metrics['pii_redaction_correct_rate']}"
        f" ({len(pii_correct)}/{len(pii_cases)})",
        f"- **False positives on benign prompts:** {metrics['false_positive_rate_benign']}"
        f" ({len(false_positives)}/{len(benign)})",
        f"- **All expectations met:** {metrics['expected_met_rate']}"
        f" ({len(expected_met)}/{len(records)})",
        f"- **End-to-end latency (includes model generation):** mean "
        f"{metrics['latency_ms_mean']} ms, p50 {metrics['latency_ms_p50']} ms, "
        f"max {metrics['latency_ms_max']} ms",
        f"- **Latency of blocked requests (guards only, model never called):** "
        f"mean {metrics['latency_ms_blocked_mean']} ms",
        "",
    ]

    misses = [r for r in records if not r["ok"]]
    if misses:
        lines += ["## Misses (reported openly)", ""]
        for record in misses:
            lines.append(
                f"- `{record['id']}` ({record['category']}): expected "
                f"**{record['expected']}**, got **{record['verdict']}**"
                + (f" - reasons: {', '.join(record['reasons'])}" if record.get("reasons") else "")
            )
        lines.append("")

    lines += [
        "## Per-case results",
        "",
        "| ID | Category | Expected | Verdict | OK | Latency ms |",
        "|---|---|---|---|---|---|",
    ]
    for record in records:
        lines.append(
            f"| {record['id']} | {record['category']} | {record['expected']} "
            f"| {record['verdict']} | {'yes' if record['ok'] else '**NO**'} "
            f"| {record.get('latency_ms') or '-'} |"
        )
    lines += [
        "",
        "---",
        "",
        "_All metrics in this file are produced by `eval/run_eval.py` against a",
        "running gateway and a real model inside GitHub Actions. Nothing is",
        "hand-written._",
        "",
    ]
    return "\n".join(lines), metrics


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gateway", default="http://127.0.0.1:8000")
    parser.add_argument("--corpus", default="eval/corpus.json")
    parser.add_argument("--out", default="reports")
    parser.add_argument("--model", default="qwen2.5:0.5b")
    parser.add_argument("--max-tokens", type=int, default=96)
    args = parser.parse_args()

    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    cases = corpus["cases"]
    records: list[dict] = []
    with httpx.Client() as client:
        for i, case in enumerate(cases, 1):
            record = run_case(client, args.gateway, case, args.model, args.max_tokens)
            records.append(record)
            print(
                f"[{i:>2}/{len(cases)}] {record['id']:<9} "
                f"expected={record['expected']:<6} got={record['verdict']:<6} "
                f"{'ok' if record['ok'] else 'MISS'}",
                flush=True,
            )

    report_md, metrics = build_report(records, args.model)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "demo-report.md").write_text(report_md, encoding="utf-8")
    (out_dir / "demo-report.json").write_text(
        json.dumps(
            {
                "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "model": args.model,
                "commit": os.environ.get("GITHUB_SHA", "local"),
                "metrics": metrics,
                "records": records,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print("\n" + json.dumps(metrics, indent=2))

    if metrics["infrastructure_errors"] == len(records):
        print("ERROR: no case reached the gateway.", file=sys.stderr)
        return 2
    if metrics["infrastructure_errors"] > 0:
        print(
            f"WARNING: {metrics['infrastructure_errors']} case(s) hit "
            "infrastructure errors.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
