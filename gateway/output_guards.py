"""Guards applied to the model's response before it reaches the client.

Two checks:
  * PII leak check -- the model may echo or invent personal data; the
    same redaction engine used on input rewrites the response.
  * JSON validation -- when the client asked for structured output, a
    minimal hand-written validator checks the response against a small
    JSON-Schema subset (type / required / properties). Kept stdlib-only
    on purpose so the logic stays fully readable.
"""

from __future__ import annotations

import json

from . import pii
from .config import Config
from .models import GuardResult, Verdict


def check_pii_leak(text: str, cfg: Config) -> GuardResult:
    """Redact PII in the model output. Result guard name: output_pii."""
    result = pii.check(text, cfg.pii)
    return GuardResult(
        guard="output_pii",
        verdict=result.verdict,
        score=result.score,
        reasons=result.reasons,
        transformed_text=result.transformed_text,
    )


def _validate_against_schema(value: object, schema: dict, path: str = "$") -> list[str]:
    """Return a list of human-readable violations (empty = valid).

    Supported keywords: type (object, array, string, number, integer,
    boolean, null), required, properties, items.
    """
    errors: list[str] = []
    expected_type = schema.get("type")
    if expected_type:
        type_map = {
            "object": dict,
            "array": list,
            "string": str,
            "number": (int, float),
            "integer": int,
            "boolean": bool,
            "null": type(None),
        }
        python_type = type_map.get(expected_type)
        if python_type is None:
            errors.append(f"{path}: unsupported schema type '{expected_type}'")
            return errors
        # bool is a subclass of int -> exclude it for number/integer.
        if expected_type in ("number", "integer") and isinstance(value, bool):
            errors.append(f"{path}: expected {expected_type}, got boolean")
            return errors
        if not isinstance(value, python_type):
            errors.append(
                f"{path}: expected {expected_type}, got {type(value).__name__}"
            )
            return errors

    if expected_type == "object":
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required key '{key}'")
        for key, sub_schema in (schema.get("properties") or {}).items():
            if key in value:
                errors.extend(
                    _validate_against_schema(value[key], sub_schema, f"{path}.{key}")
                )
    elif expected_type == "array":
        item_schema = schema.get("items")
        if item_schema:
            for i, item in enumerate(value):
                errors.extend(
                    _validate_against_schema(item, item_schema, f"{path}[{i}]")
                )
    return errors


def check_json(text: str, schema: dict, cfg: Config) -> GuardResult:
    """Validate that the response is JSON matching the requested schema."""
    action = (
        Verdict.BLOCK if cfg.output.json_validation_action == "block" else Verdict.FLAG
    )
    # Models often wrap JSON in markdown fences -- strip them first.
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        if stripped.startswith("json"):
            stripped = stripped[4:]
        stripped = stripped.strip()
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError as exc:
        return GuardResult(
            guard="json_schema",
            verdict=action,
            score=1.0,
            reasons=[f"json.parse_error: {exc.msg}"],
        )
    violations = _validate_against_schema(parsed, schema)
    if violations:
        return GuardResult(
            guard="json_schema",
            verdict=action,
            score=1.0,
            reasons=[f"json.schema: {v}" for v in violations[:5]],
        )
    return GuardResult(guard="json_schema", verdict=Verdict.PASS)
