"""Unit tests for the output guards."""

from gateway import output_guards
from gateway.config import Config
from gateway.models import Verdict

CFG = Config()

PERSON_SCHEMA = {
    "type": "object",
    "required": ["name", "age"],
    "properties": {
        "name": {"type": "string"},
        "age": {"type": "integer"},
        "tags": {"type": "array", "items": {"type": "string"}},
    },
}


def test_valid_json_passes():
    result = output_guards.check_json('{"name": "Ada", "age": 36}', PERSON_SCHEMA, CFG)
    assert result.verdict == Verdict.PASS


def test_json_in_markdown_fences_is_unwrapped():
    text = '```json\n{"name": "Ada", "age": 36}\n```'
    result = output_guards.check_json(text, PERSON_SCHEMA, CFG)
    assert result.verdict == Verdict.PASS


def test_missing_required_key_is_flagged():
    result = output_guards.check_json('{"name": "Ada"}', PERSON_SCHEMA, CFG)
    assert result.verdict == Verdict.FLAG
    assert any("missing required key 'age'" in r for r in result.reasons)


def test_wrong_type_is_flagged():
    result = output_guards.check_json(
        '{"name": "Ada", "age": "thirty-six"}', PERSON_SCHEMA, CFG
    )
    assert result.verdict == Verdict.FLAG
    assert any("expected integer" in r for r in result.reasons)


def test_unparseable_output_is_flagged():
    result = output_guards.check_json("Sorry, here is prose.", PERSON_SCHEMA, CFG)
    assert result.verdict == Verdict.FLAG
    assert any("json.parse_error" in r for r in result.reasons)


def test_array_items_are_validated():
    result = output_guards.check_json(
        '{"name": "Ada", "age": 36, "tags": ["a", 7]}', PERSON_SCHEMA, CFG
    )
    assert result.verdict == Verdict.FLAG


def test_block_action_configurable():
    cfg = Config()
    cfg.output.json_validation_action = "block"
    result = output_guards.check_json("not json", PERSON_SCHEMA, cfg)
    assert result.verdict == Verdict.BLOCK


def test_output_pii_leak_is_redacted():
    result = output_guards.check_pii_leak(
        "Sure! The customer's email is maria.huber@example.com.", CFG
    )
    assert result.verdict == Verdict.REDACT
    assert result.guard == "output_pii"
    assert "maria.huber@example.com" not in (result.transformed_text or "")


def test_clean_output_passes():
    result = output_guards.check_pii_leak("The invoice total is 240 euros.", CFG)
    assert result.verdict == Verdict.PASS
