# modules/validation/validation.py

import re
from html import escape

# ----------------------------------------------------------
# Patterns for safe input
# ----------------------------------------------------------
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,20}$")
EMAIL_PATTERN    = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# ----------------------------------------------------------
# Dangerous patterns (SQLi + XSS)
# ----------------------------------------------------------
SQLI_PATTERNS = [
    r"(\bor\b|\band\b).*(=|<|>)",
    r"(--|\#|\/\*)",
    r"select\s+.*from",
    r"insert\s+into",
    r"drop\s+table",
]

XSS_PATTERNS = [
    r"<script.*?>",
    r"onerror\s*=",
    r"onload\s*=",
]

# ----------------------------------------------------------
# Helper: detect suspicious patterns
# ----------------------------------------------------------
def contains_pattern(text: str, patterns: list) -> bool:
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return True
    return False


# ----------------------------------------------------------
# Validate username
# ----------------------------------------------------------
def validate_username(username: str) -> bool:
    """
    Rules:
    - 3–20 characters
    - letters, numbers, _, -, .
    - no SQLi / XSS
    """
    if not username:
        return False

    if len(username) < 3 or len(username) > 20:
        return False

    if not USERNAME_PATTERN.match(username):
        return False

    return True


# ----------------------------------------------------------
# Validate email
# ----------------------------------------------------------
def validate_email(email: str) -> bool:
    if not email:
        return False

    return EMAIL_PATTERN.match(email) is not None


# ----------------------------------------------------------
# Validate general text
# ----------------------------------------------------------
def validate_text(text: str) -> bool:
    """
    - Reject SQL injection patterns
    - Reject XSS patterns
    - Max length 500
    """
    if not text:
        return False

    if contains_pattern(text, SQLI_PATTERNS):
        return False

    if contains_pattern(text, XSS_PATTERNS):
        return False

    if len(text) > 500:
        return False

    return True


# ----------------------------------------------------------
# Sanitize output (escape HTML)
# ----------------------------------------------------------
def sanitize(text: str) -> str:
    """
    Replace < > & etc with safe HTML entities
    """
    return escape(text)
