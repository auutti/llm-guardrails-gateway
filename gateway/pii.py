"""PII detection and redaction.

Pure regex + checksum approach: fast (microseconds), dependency-free and
fully explainable -- every redaction can be traced to a named rule.

Two validators cut false positives drastically:
  * credit cards must pass the Luhn checksum
  * IBANs must pass the ISO 13616 mod-97 checksum
A random 16-digit number or an IBAN-looking string with a typo is
therefore NOT redacted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .config import PiiConfig
from .models import GuardResult, Verdict


@dataclass
class PiiMatch:
    rule_id: str
    start: int
    end: int
    text: str
    placeholder: str


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def luhn_valid(number: str) -> bool:
    """Luhn checksum used by all major card networks."""
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    checksum = 0
    # Double every second digit from the right.
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def iban_valid(candidate: str) -> bool:
    """ISO 13616 mod-97 check: move the first 4 chars to the end,
    convert letters to numbers (A=10 ... Z=35) and check mod 97 == 1."""
    compact = re.sub(r"\s", "", candidate).upper()
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    converted = "".join(
        str(ord(ch) - 55) if ch.isalpha() else ch for ch in rearranged
    )
    try:
        return int(converted) % 97 == 1
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Rules: (rule_id, regex, placeholder, validator or None)
# ---------------------------------------------------------------------------

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b")

_CREDIT_CARD = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")

# International numbers (+43 ..., 0043 ...) and national numbers with a
# separator (0664 1234567). A post-filter requires at least 8 digits so
# years, prices and IDs are not caught.
_PHONE = re.compile(
    r"(?:\+|00)[1-9]\d{0,2}[\s\-/]?(?:\(?\d{1,4}\)?[\s\-/]?){1,4}\d{2,}"
    r"|\b0\d{2,4}[\s\-/]\d{4,}(?:[\s\-/]?\d+)?\b"
)

_ADDRESS = re.compile(
    # German-style street + house number: "Hauptstraße 12", "Lindenweg 3a"
    r"\b[A-ZÄÖÜ][a-zäöüß\-]+(?:straße|strasse|str\.|weg|allee|platz|gasse|ring)"
    r"\s+\d{1,4}[a-z]?\b"
    # English-style: "221B Baker Street", "10 Downing Street"
    r"|\b\d{1,5}[A-Z]?\s+[A-Z][a-z]+(?:\s[A-Z][a-z]+)?"
    r"\s+(?:Street|St\.|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Lane|Ln\.?|Drive|Dr\.?)\b"
)


def _phone_post_filter(match_text: str) -> bool:
    return len(re.sub(r"\D", "", match_text)) >= 8


# Order matters: credit_card runs before phone because both match digit
# sequences and the card validator is stricter.
RULES: list[tuple[str, re.Pattern, str, object]] = [
    ("pii.email", _EMAIL, "[EMAIL]", None),
    ("pii.iban", _IBAN, "[IBAN]", iban_valid),
    ("pii.credit_card", _CREDIT_CARD, "[CARD]", luhn_valid),
    ("pii.phone", _PHONE, "[PHONE]", _phone_post_filter),
    ("pii.address", _ADDRESS, "[ADDRESS]", None),
]

_RULE_TO_CONFIG_KEY = {
    "pii.email": "email",
    "pii.iban": "iban",
    "pii.credit_card": "credit_card",
    "pii.phone": "phone",
    "pii.address": "address",
}


def detect(text: str, cfg: PiiConfig | None = None) -> list[PiiMatch]:
    """Find all PII spans. Overlapping spans keep the earliest/longest match."""
    cfg = cfg or PiiConfig()
    # Anything shaped like an IBAN is treated as one unit: if its
    # checksum fails it is an ordinary reference code, and the digit
    # groups inside it must not be picked up as a card or phone number.
    iban_shaped = [(m.start(), m.end()) for m in _IBAN.finditer(text)]

    def inside_iban_shape(start: int, end: int) -> bool:
        return any(start < e and end > s for s, e in iban_shaped)

    matches: list[PiiMatch] = []
    for rule_id, pattern, placeholder, validator in RULES:
        if not cfg.enabled.get(_RULE_TO_CONFIG_KEY[rule_id], True):
            continue
        for m in pattern.finditer(text):
            if validator is not None and not validator(m.group(0)):
                continue
            if rule_id in ("pii.credit_card", "pii.phone") and inside_iban_shape(
                m.start(), m.end()
            ):
                continue
            matches.append(
                PiiMatch(rule_id, m.start(), m.end(), m.group(0), placeholder)
            )

    # Resolve overlaps: sort by start, then longer match first; drop any
    # match overlapping an already accepted one (e.g. phone inside card).
    matches.sort(key=lambda x: (x.start, -(x.end - x.start)))
    accepted: list[PiiMatch] = []
    last_end = -1
    for m in matches:
        if m.start >= last_end:
            accepted.append(m)
            last_end = m.end
    return accepted


def redact(text: str, cfg: PiiConfig | None = None) -> tuple[str, list[str]]:
    """Replace detected PII with placeholders.

    Returns (redacted_text, matched_rule_ids).
    """
    matches = detect(text, cfg)
    if not matches:
        return text, []
    parts: list[str] = []
    cursor = 0
    for m in matches:
        parts.append(text[cursor:m.start])
        parts.append(m.placeholder)
        cursor = m.end
    parts.append(text[cursor:])
    return "".join(parts), [m.rule_id for m in matches]


def check(text: str, cfg: PiiConfig | None = None) -> GuardResult:
    """Guard interface: REDACT if any PII was found, otherwise PASS."""
    redacted, rule_ids = redact(text, cfg)
    if rule_ids:
        return GuardResult(
            guard="pii",
            verdict=Verdict.REDACT,
            score=1.0,
            reasons=sorted(set(rule_ids)),
            transformed_text=redacted,
        )
    return GuardResult(guard="pii", verdict=Verdict.PASS)
