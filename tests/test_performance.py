"""Denial-of-service regression tests.

A guard that can be stalled by one crafted request is itself a
vulnerability. Each case below is a long input designed to trigger
catastrophic backtracking in a naive regular expression; every guard
must stay fast on all of them.
"""

import time

import pytest

from gateway import injection, pii
from gateway.config import Config
from gateway.pipeline import run_input_guards, run_output_guards

SIZE = 100_000
BUDGET_SECONDS = 2.0

HOSTILE_INPUTS = {
    "letters_without_at_sign": "a" * SIZE,
    "long_base64_like_run": "aGVsbG8" * (SIZE // 7),
    "unclosed_markdown_images": "![" * (SIZE // 2),
    "digits_and_spaces": "1 " * (SIZE // 2),
    "hyphenated_word": "A" + "a-" * (SIZE // 2),
    "repeated_trigger_word": "ignore " * (SIZE // 7),
    "repeated_exfil_prefix": "send this " * (SIZE // 10),
    "plus_signs_and_digits": "+1 " * (SIZE // 3),
}


@pytest.mark.parametrize("name", sorted(HOSTILE_INPUTS))
def test_guards_stay_fast_on_hostile_input(name):
    text = HOSTILE_INPUTS[name]
    cfg = Config()
    started = time.perf_counter()
    pii.redact(text)
    injection.score_text(text)
    run_input_guards(text, cfg)
    run_output_guards(text, cfg)
    elapsed = time.perf_counter() - started
    assert elapsed < BUDGET_SECONDS, f"{name}: guards took {elapsed:.2f}s"
