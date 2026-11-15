import re
from typing import List, Tuple

# Phrases indicating negation or defensive advice
NEGATION_PATTERNS = [
    re.compile(r"\bnever\s+(?:share|give|provide|send|disclose|reveal|enter)\b", re.IGNORECASE),
    re.compile(r"\bdo\s+not\s+(?:share|give|provide|send|disclose|reveal|click|download|install)\b", re.IGNORECASE),
    re.compile(r"\bdon['’]t\s+(?:share|give|provide|send|disclose|reveal|click|download|install)\b", re.IGNORECASE),
    re.compile(r"\bwill\s+never\s+(?:ask|call|request|demand|send)\b", re.IGNORECASE),
    re.compile(r"\bshould\s+never\s+(?:be\s+shared|share|disclose)\b", re.IGNORECASE),
    re.compile(r"\brefrain\s+from\s+(?:sharing|sending|disclosing|clicking)\b", re.IGNORECASE),
    re.compile(r"\bno\s+one\s+should\s+ask\b", re.IGNORECASE),
    re.compile(r"\bwe\s+never\s+ask\b", re.IGNORECASE),
]

# Educational or security advisory markers
EDUCATIONAL_HEADERS = [
    re.compile(r"\bsecurity\s+tip\b", re.IGNORECASE),
    re.compile(r"\bcybersecurity\s+awareness\b", re.IGNORECASE),
    re.compile(r"\bscam\s+alert\b", re.IGNORECASE),
    re.compile(r"\bfraud\s+warning\b", re.IGNORECASE),
    re.compile(r"\beducational\s+reminder\b", re.IGNORECASE),
    re.compile(r"\bpublic\s+advisory\b", re.IGNORECASE),
    re.compile(r"\bbeware\s+of\s+(?:phishing|fraud|scams|fake|impersonators)\b", re.IGNORECASE),
    re.compile(r"\bhow\s+to\s+protect\s+yourself\b", re.IGNORECASE),
    re.compile(r"\bsafety\s+recommendation\b", re.IGNORECASE),
]


def is_negated_or_educational(clause_or_sentence: str) -> bool:
    """
    Checks if a given sentence or clause explicitly advises AGAINST an action,
    or is written in an educational/defensive context.
    """
    text = clause_or_sentence.strip()
    if not text:
        return False

    for pat in NEGATION_PATTERNS:
        if pat.search(text):
            return True

    for pat in EDUCATIONAL_HEADERS:
        if pat.search(text):
            return True

    return False


def is_overall_educational_content(full_text: str) -> bool:
    """
    Checks whether the entire text is primarily an educational/security awareness bulletin
    rather than an active threat/scam message.
    """
    text = full_text.strip()
    header_count = sum(1 for pat in EDUCATIONAL_HEADERS if pat.search(text))
    negation_count = sum(1 for pat in NEGATION_PATTERNS if pat.search(text))

    # If the text starts with an advisory header and contains defensive guidance
    if header_count >= 1 and negation_count >= 1:
        return True

    if header_count >= 2:
        return True

    return False
