from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import math
import re
from typing import Iterable


@dataclass(frozen=True)
class SecretPattern:
    provider: str
    label: str
    regex: re.Pattern[str]
    confidence: str = "high"


@dataclass(frozen=True)
class Detection:
    provider: str
    label: str
    fingerprint: str
    masked_secret: str
    line_number: int
    evidence: str
    confidence: str


def _compiled(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# Patterns intentionally target recognizable provider prefixes or an explicit
# provider-specific variable name. Generic high-entropy strings are not treated
# as secrets because that creates too many false positives.
PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "OpenAI",
        "OpenAI API key",
        _compiled(r"(?P<secret>sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,})"),
    ),
    SecretPattern(
        "Anthropic",
        "Anthropic API key",
        _compiled(r"(?P<secret>sk-ant-[A-Za-z0-9_-]{20,})"),
    ),
    SecretPattern(
        "Google AI",
        "Google/Gemini API key",
        _compiled(r"(?P<secret>AIza[0-9A-Za-z_-]{30,})"),
    ),
    SecretPattern(
        "Hugging Face",
        "Hugging Face access token",
        _compiled(r"(?P<secret>hf_[A-Za-z0-9]{24,})"),
    ),
    SecretPattern(
        "Groq",
        "Groq API key",
        _compiled(r"(?P<secret>gsk_[A-Za-z0-9]{24,})"),
    ),
    SecretPattern(
        "Replicate",
        "Replicate API token",
        _compiled(r"(?P<secret>r8_[A-Za-z0-9]{24,})"),
    ),
    SecretPattern(
        "Azure OpenAI",
        "Azure OpenAI key",
        _compiled(
            r"(?:AZURE_OPENAI_API_KEY|AZURE_AI_API_KEY)\s*[:=]\s*['\"]?"
            r"(?P<secret>[a-f0-9]{32})"
        ),
    ),
)


PLACEHOLDER_WORDS = (
    "your_api",
    "your-api",
    "your_key",
    "your-key",
    "replace_me",
    "replace-me",
    "example",
    "placeholder",
    "dummy",
    "sample",
    "test_key",
    "test-key",
)


def _looks_like_placeholder(secret: str) -> bool:
    lowered = secret.lower()
    if any(word in lowered for word in PLACEHOLDER_WORDS):
        return True
    payload = re.sub(r"^(?:sk-(?:proj-|svcacct-)?|sk-ant-|AIza|hf_|gsk_|r8_)", "", secret, flags=re.I)
    if len(set(payload.lower())) <= 4:
        return True
    return _shannon_entropy(payload) < 2.6


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _mask(secret: str) -> str:
    suffix = secret[-4:] if len(secret) >= 4 else "????"
    return f"••••••••{suffix}"


def _fingerprint(secret: str, fingerprint_key: bytes) -> str:
    return hmac.new(fingerprint_key, secret.encode("utf-8"), hashlib.sha256).hexdigest()


def _redact_line(line: str) -> str:
    redacted = line
    for pattern in PATTERNS:
        redacted = pattern.regex.sub(lambda match: match.group(0).replace(match.group("secret"), "[REDACTED]"), redacted)
    redacted = redacted.strip().replace("\t", "  ")
    return redacted[:240] + ("…" if len(redacted) > 240 else "")


def scan_text(text: str, fingerprint_key: bytes) -> list[Detection]:
    """Find candidate secrets without returning or persisting their raw values."""
    detections: list[Detection] = []
    seen: set[tuple[str, str, int]] = set()

    for line_number, line in enumerate(text.splitlines(), start=1):
        for pattern in PATTERNS:
            for match in pattern.regex.finditer(line):
                secret = match.group("secret")
                if _looks_like_placeholder(secret):
                    continue
                fingerprint = _fingerprint(secret, fingerprint_key)
                identity = (pattern.provider, fingerprint, line_number)
                if identity in seen:
                    continue
                seen.add(identity)
                detections.append(
                    Detection(
                        provider=pattern.provider,
                        label=pattern.label,
                        fingerprint=fingerprint,
                        masked_secret=_mask(secret),
                        line_number=line_number,
                        evidence=_redact_line(line),
                        confidence=pattern.confidence,
                    )
                )
    return detections


def supported_providers() -> Iterable[str]:
    return tuple(dict.fromkeys(pattern.provider for pattern in PATTERNS))

