"""The gateway itself.

A FastAPI application exposing an OpenAI-compatible
POST /v1/chat/completions endpoint. Flow per request:

    client -> [input guards] -> upstream LLM -> [output guards] -> client
                   |                                  |
                   +------------- audit log ----------+

* BLOCK on input returns an OpenAI-style 400 error without ever calling
  the upstream model (a blocked attack costs zero tokens).
* REDACT rewrites the user messages before they are forwarded.
* Output BLOCK replaces the model text with a neutral refusal rather
  than failing the request -- tokens were already spent, and the client
  still gets a well-formed response plus honest headers.

Guard verdicts are exposed in X-Guardrails-* response headers and,
optionally, in a `guardrails` object inside the response body when the
request contains `"guardrails": {"include_metadata": true}`.
"""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import pii
from .audit import AuditLogger, sha256_text
from .config import Config, load_config
from .models import Verdict, max_verdict
from .pipeline import run_input_guards, run_output_guards

REFUSAL_TEXT = (
    "This response was withheld by the guardrails layer because it "
    "violated the configured content policy."
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _error_body(message: str, code: str) -> dict:
    """OpenAI-style error envelope."""
    return {
        "error": {
            "message": message,
            "type": "invalid_request_error",
            "code": code,
        }
    }


def create_app(
    config_path: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """Build the FastAPI app.

    `transport` lets tests inject an httpx.MockTransport so the full
    request flow can be exercised without any real upstream server.
    """
    cfg: Config = load_config(config_path)
    audit = AuditLogger(cfg.audit.path)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.client = httpx.AsyncClient(
            transport=transport,
            timeout=cfg.upstream.timeout_seconds,
        )
        yield
        await app.state.client.aclose()

    app = FastAPI(title="LLM Guardrails Gateway", lifespan=lifespan)

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "upstream": cfg.upstream.base_url}

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        started = time.perf_counter()
        request_id = str(uuid.uuid4())

        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400,
                content=_error_body("Request body is not valid JSON.", "invalid_json"),
            )

        messages = body.get("messages") or []
        # Non-OpenAI extension field; removed before forwarding upstream.
        guardrails_opts = body.pop("guardrails", {}) or {}
        include_metadata = bool(guardrails_opts.get("include_metadata"))
        json_schema = guardrails_opts.get("json_schema")

        # ---- Input guards -------------------------------------------------
        # PII is redacted per user message; injection/policy run on the
        # concatenation of all (already redacted) user messages.
        pii_reasons: list[str] = []
        pii_hit = False
        user_texts: list[str] = []
        for message in messages:
            if message.get("role") != "user":
                continue
            content = message.get("content")
            if not isinstance(content, str):
                continue
            redacted, rule_ids = pii.redact(content, cfg.pii)
            if rule_ids:
                pii_hit = True
                pii_reasons.extend(rule_ids)
                message["content"] = redacted
            user_texts.append(message.get("content", ""))

        combined_input = "\n".join(user_texts)
        input_result = run_input_guards(combined_input, cfg)
        # Replace the pipeline's PII result with the per-message outcome
        # (the pipeline saw already-redacted text, so it reports PASS).
        for guard_result in input_result.results:
            if guard_result.guard == "pii":
                if pii_hit:
                    guard_result.verdict = Verdict.REDACT
                    guard_result.score = 1.0
                    guard_result.reasons = sorted(set(pii_reasons))
                break
        input_result.verdict = max_verdict(
            [r.verdict for r in input_result.results]
        )

        prompt_hash = sha256_text(combined_input)
        base_record = {
            "ts": _utc_now(),
            "request_id": request_id,
            "model": body.get("model", ""),
            "input_verdict": input_result.verdict.value,
            "guard_results": [r.to_dict() for r in input_result.results],
            "prompt_sha256": prompt_hash,
            "prompt_chars": len(combined_input),
        }
        if cfg.audit.log_content:
            base_record["prompt_text"] = combined_input

        def guard_headers(output_summary: str = "", overall: Verdict | None = None) -> dict:
            total_ms = round((time.perf_counter() - started) * 1000, 1)
            headers = {
                "X-Guardrails-Verdict": (overall or input_result.verdict).value,
                "X-Guardrails-Input": input_result.header_summary(),
                "X-Guardrails-Request-Id": request_id,
                "X-Guardrails-Latency-Ms": str(total_ms),
            }
            if output_summary:
                headers["X-Guardrails-Output"] = output_summary
            return headers

        def metadata(output_result=None) -> dict:
            data = {
                "request_id": request_id,
                "input": input_result.to_dict(),
                "redacted_input": combined_input
                if input_result.verdict != Verdict.PASS or pii_hit
                else None,
            }
            if output_result is not None:
                data["output"] = output_result.to_dict()
            return data

        if input_result.verdict == Verdict.BLOCK:
            audit.log(
                {
                    **base_record,
                    "outcome": "blocked",
                    "total_ms": round((time.perf_counter() - started) * 1000, 1),
                }
            )
            content = _error_body(
                "Request blocked by guardrails: "
                + ", ".join(input_result.all_reasons()),
                "guardrails_blocked",
            )
            if include_metadata:
                content["guardrails"] = metadata()
            return JSONResponse(
                status_code=400, content=content, headers=guard_headers()
            )

        # ---- Forward to upstream -----------------------------------------
        upstream_url = cfg.upstream.base_url.rstrip("/") + "/chat/completions"
        upstream_started = time.perf_counter()
        try:
            upstream_response = await request.app.state.client.post(
                upstream_url, json=body
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            audit.log(
                {
                    **base_record,
                    "outcome": "upstream_error",
                    "error": type(exc).__name__,
                    "total_ms": round((time.perf_counter() - started) * 1000, 1),
                }
            )
            return JSONResponse(
                status_code=502,
                content=_error_body(
                    f"Upstream LLM unreachable: {type(exc).__name__}",
                    "upstream_unavailable",
                ),
                headers=guard_headers(),
            )
        upstream_ms = round((time.perf_counter() - upstream_started) * 1000, 1)

        if upstream_response.status_code != 200:
            audit.log(
                {
                    **base_record,
                    "outcome": "upstream_error",
                    "upstream_status": upstream_response.status_code,
                    "upstream_ms": upstream_ms,
                    "total_ms": round((time.perf_counter() - started) * 1000, 1),
                }
            )
            return JSONResponse(
                status_code=upstream_response.status_code,
                content=upstream_response.json()
                if "application/json"
                in upstream_response.headers.get("content-type", "")
                else _error_body("Upstream error.", "upstream_error"),
                headers=guard_headers(),
            )

        response_body = upstream_response.json()

        # ---- Output guards ------------------------------------------------
        output_result = None
        completion_text = ""
        choices = response_body.get("choices") or []
        if choices and isinstance(choices[0].get("message", {}).get("content"), str):
            completion_text = choices[0]["message"]["content"]
            output_result = run_output_guards(completion_text, cfg, json_schema)
            if output_result.verdict == Verdict.BLOCK:
                choices[0]["message"]["content"] = REFUSAL_TEXT
            elif output_result.verdict == Verdict.REDACT:
                choices[0]["message"]["content"] = output_result.text

        overall = max_verdict(
            [input_result.verdict]
            + ([output_result.verdict] if output_result else [])
        )

        usage = response_body.get("usage") or {}
        audit.log(
            {
                **base_record,
                "output_verdict": output_result.verdict.value
                if output_result
                else "pass",
                "output_guard_results": [r.to_dict() for r in output_result.results]
                if output_result
                else [],
                "completion_chars": len(completion_text),
                "usage": {
                    "prompt_tokens": usage.get("prompt_tokens"),
                    "completion_tokens": usage.get("completion_tokens"),
                },
                "upstream_ms": upstream_ms,
                "total_ms": round((time.perf_counter() - started) * 1000, 1),
                "outcome": "completed",
            }
        )

        if include_metadata:
            response_body["guardrails"] = metadata(output_result)

        return JSONResponse(
            status_code=200,
            content=response_body,
            headers=guard_headers(
                output_summary=output_result.header_summary()
                if output_result
                else "",
                overall=overall,
            ),
        )

    return app


# Default instance used by `uvicorn gateway.app:app`.
app = create_app()
