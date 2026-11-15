import re
import unicodedata
from typing import List, Tuple


# Zero-width and invisible unicode characters often used for filter evasion
ZERO_WIDTH_CHARS = re.compile(r"[\u200B-\u200D\uFEFF\u2060\u200E\u200F\u00AD]")

# Smart quotes and dashes normalization map
CHAR_REPLACEMENTS = {
    "\u2018": "'",
    "\u2019": "'",
    "\u201C": '"',
    "\u201D": '"',
    "\u2013": "-",
    "\u2014": "-",
    "\u2026": "...",
}


def normalize_text(text: str) -> str:
    """
    Normalizes text for consistent analysis:
    - Normalizes unicode using NFKC (combining characters, compatibility forms)
    - Strips zero-width and invisible characters
    - Normalizes smart punctuation
    - Normalizes multi-spaces to single space
    """
    if not text:
        return ""

    # NFKC decomposition & recomposition
    normalized = unicodedata.normalize("NFKC", text)

    # Remove zero-width characters
    normalized = ZERO_WIDTH_CHARS.sub("", normalized)

    # Replace fancy punctuation
    for orig, repl in CHAR_REPLACEMENTS.items():
        normalized = normalized.replace(orig, repl)

    # Normalize excessive spaces (tabs, multiple spaces) while retaining newlines
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in normalized.splitlines()]
    return "\n".join(lines).strip()


def extract_sentences(text: str) -> List[str]:
    """
    Splits text into approximate sentence or clause boundaries.
    """
    normalized = normalize_text(text)
    # Split on sentence terminals or newlines
    sentences = re.split(r"(?<=[.!?\n])\s+", normalized)
    return [s.strip() for s in sentences if s.strip()]


def find_evidence_snippet(full_text: str, match_text: str, max_chars: int = 140) -> str:
    """
    Extracts a contextual snippet from original text around a match.
    """
    idx = full_text.lower().find(match_text.lower())
    if idx == -1:
        return match_text[:max_chars]

    start = max(0, idx - 20)
    end = min(len(full_text), idx + len(match_text) + 20)
    snippet = full_text[start:end].strip()

    if start > 0:
        snippet = "..." + snippet
    if end < len(full_text):
        snippet = snippet + "..."
    return snippet
