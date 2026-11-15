import ipaddress
import re
import urllib.parse
from typing import Tuple, Optional
from app.config import settings
from app.models.requests import InputType


DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file", "blob", "about"}
SUPPORTED_WEB_SCHEMES = {"http", "https"}


class ValidationError(Exception):
    def __init__(self, message: str, code: str = "validation_error"):
        self.message = message
        self.code = code
        super().__init__(self.message)


def validate_input(input_type: InputType, content: str) -> Tuple[bool, Optional[str]]:
    """
    Validates input type and content.
    Returns (is_valid, error_message).
    Empty or whitespace content is deferred to is_content_insufficient.
    """
    if content is None:
        return True, None

    trimmed = content.strip()
    if not trimmed:
        return True, None

    if len(trimmed) > settings.MAX_CONTENT_LENGTH:
        return False, f"Input length ({len(trimmed)} chars) exceeds maximum allowed limit of {settings.MAX_CONTENT_LENGTH:,} characters."

    if input_type == InputType.URL:
        # Check all scheme instances in the submitted text
        for token in trimmed.split():
            if "://" in token:
                scheme = token.split("://", 1)[0].lower().strip()
                scheme = re.sub(r"^[^a-z]+", "", scheme)
                # Unsupported network schemes (e.g. ftp://, ldap://) are rejected with 422
                if scheme and scheme not in SUPPORTED_WEB_SCHEMES and scheme not in DANGEROUS_SCHEMES:
                    return False, f"Unsupported URL scheme: '{scheme}:'. Inspectra supports HTTP and HTTPS URLs."

    return True, None


def is_content_insufficient(content: str, input_type: InputType = InputType.MESSAGE) -> bool:
    """
    Determines if content is too short or lacks meaningful characters to assess.
    For URL input: accepts bare IPs, short hostnames (e.g. t.co, t.me), or valid hostnames.
    For message/app_request: requires at least 4 alphabetic characters.
    """
    if not content:
        return True
    trimmed = content.strip()
    if not trimmed:
        return True

    if input_type == InputType.URL:
        # Check if bare IP address
        clean_host = trimmed.split("/")[0].split(":")[0].strip("[]")
        try:
            ipaddress.ip_address(clean_host)
            return False
        except ValueError:
            pass

        # Check if host has a dot (e.g. t.co, domain.com) or valid host structure
        full_url = trimmed if "://" in trimmed else f"http://{trimmed}"
        try:
            parsed = urllib.parse.urlsplit(full_url)
            host = parsed.hostname or parsed.netloc.split(":")[0]
            if host and "." in host:
                return False
        except Exception:
            pass

    stripped = re.sub(r"[\s\d\W_]+", "", content)
    return len(stripped) < 4
