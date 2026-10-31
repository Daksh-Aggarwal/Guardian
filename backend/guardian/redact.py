"""Secret redaction layer to sanitize sensitive material before external transmission."""
import re
from typing import Any

# Regex patterns for high-risk credentials, tokens, and private keys
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9_\- ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_\- ]*PRIVATE KEY-----",
    re.IGNORECASE
)
AWS_KEY_PATTERN = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
GOOGLE_API_KEY_PATTERN = re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")
GITHUB_TOKEN_PATTERN = re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59})\b")
SLACK_TOKEN_PATTERN = re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,72})\b")
JWT_PATTERN = re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b")
AUTH_HEADER_PATTERN = re.compile(r"(Authorization\s*:\s*(?:Bearer|Basic)\s+)[^\s\r\n]+", re.IGNORECASE)
BASIC_AUTH_URL_PATTERN = re.compile(r"(https?://)([^:\s@/]+):([^@\s/]+)@", re.IGNORECASE)
GENERIC_SECRET_ASSIGN_PATTERN = re.compile(
    r"((?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"])[^'\"\r\n]{4,}(['\"])",
    re.IGNORECASE
)

def redact_text(text: str) -> str:
    """Redacts potential secrets, credentials, tokens, and private keys from text."""
    if not text:
        return text

    sanitized = PRIVATE_KEY_PATTERN.sub("[REDACTED_PRIVATE_KEY]", text)
    sanitized = AWS_KEY_PATTERN.sub("[REDACTED_AWS_KEY]", sanitized)
    sanitized = GOOGLE_API_KEY_PATTERN.sub("[REDACTED_GOOGLE_KEY]", sanitized)
    sanitized = GITHUB_TOKEN_PATTERN.sub("[REDACTED_GITHUB_TOKEN]", sanitized)
    sanitized = SLACK_TOKEN_PATTERN.sub("[REDACTED_SLACK_TOKEN]", sanitized)
    sanitized = JWT_PATTERN.sub("[REDACTED_JWT]", sanitized)
    sanitized = AUTH_HEADER_PATTERN.sub(r"\1[REDACTED_AUTH_TOKEN]", sanitized)
    sanitized = BASIC_AUTH_URL_PATTERN.sub(r"\1\2:[REDACTED_PASSWORD]@", sanitized)
    sanitized = GENERIC_SECRET_ASSIGN_PATTERN.sub(r"\1[REDACTED_SECRET]\2", sanitized)

    return sanitized

def redact_data(data: Any) -> Any:
    """Recursively redacts strings within dictionaries, lists, or primitive types."""
    if isinstance(data, str):
        return redact_text(data)
    elif isinstance(data, dict):
        return {k: redact_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [redact_data(item) for item in data]
    return data
