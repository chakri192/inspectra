import ipaddress
import re
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional
import tldextract

# Initialize offline extractor without network lookups
_offline_extractor = tldextract.TLDExtract(suffix_list_urls=None)

# Popular URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "rebrand.ly", "ow.ly", "buff.ly", "shorte.st", "t.me", "rb.gy",
    "qr.ae", "v.gd", "adf.ly", "bl.ink"
}

# TLDs frequently abused in mass disposable phishing campaigns
SUSPICIOUS_TLDS = {
    "top", "xyz", "zip", "mov", "fit", "kim", "tk", "ml", "ga",
    "cf", "gq", "work", "click", "buzz", "rest", "country", "icu", "cam", "vip"
}

# High-profile brands frequently targeted by brand impersonation
POPULAR_BRANDS = [
    "paypal", "apple", "google", "microsoft", "netflix", "amazon",
    "chase", "bankofamerica", "wellsfargo", "citi", "facebook",
    "instagram", "whatsapp", "irs", "cbi", "police", "fedex", "dhl",
    "usps", "steam", "coinbase", "binance", "metamask", "outlook",
    "office365", "dropbox", "icloud", "yahoo", "barclays", "hsbc"
]

# Executable or mobile package extensions
EXECUTABLE_EXTENSIONS = {
    ".apk", ".exe", ".scr", ".bat", ".cmd", ".msi", ".vbs",
    ".ps1", ".dmg", ".ipa", ".jar", ".dex", ".dll", ".hta", ".iso"
}

# Confusable homoglyph characters (Cyrillic/Greek looking like Latin)
HOMOGLYPH_CHARS = {
    '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u0458': 'j', '\u0455': 's', '\u04BB': 'h', '\u0410': 'A',
    '\u0412': 'B', '\u0415': 'E', '\u041A': 'K', '\u041C': 'M',
    '\u041D': 'H', '\u041E': 'O', '\u0420': 'P', '\u0421': 'C',
    '\u0422': 'T', '\u0425': 'X', '\u03BF': 'o', '\u03C1': 'p',
    '\u03B1': 'a', '\u03BD': 'v'
}

DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file", "blob", "about"}


@dataclass
class ParsedUrl:
    raw_url: str
    scheme: str = ""
    netloc: str = ""
    hostname: str = ""
    port: Optional[int] = None
    path: str = ""
    query: str = ""
    fragment: str = ""
    userinfo: str = ""
    subdomain: str = ""
    domain: str = ""
    suffix: str = ""
    registrable_domain: str = ""
    
    # Security attributes
    is_ip: bool = False
    is_shortener: bool = False
    has_suspicious_tld: bool = False
    has_homoglyphs: bool = False
    homoglyph_details: str = ""
    has_embedded_credentials: bool = False
    has_executable_extension: bool = False
    executable_ext: str = ""
    misleading_subdomain: bool = False
    impersonated_brand: str = ""
    has_suspicious_encoding: bool = False
    has_at_symbol: bool = False
    is_dangerous_scheme: bool = False
    dangerous_scheme_name: str = ""


def is_ip_address(host: str) -> bool:
    """Checks if hostname is an IPv4, IPv6, or numeric/hex encoded IP."""
    if not host:
        return False

    clean_host = host.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        pass

    if clean_host.startswith("0x") or clean_host.isdigit():
        try:
            val = int(clean_host, 0)
            if 0 <= val <= 0xFFFFFFFF:
                return True
        except ValueError:
            pass

    return False


def check_homoglyphs(hostname: str) -> tuple[bool, str]:
    """Detects Cyrillic, Greek, or Punycode homoglyphs in hostname."""
    if not hostname:
        return False, ""

    if hostname.lower().startswith("xn--") or ".xn--" in hostname.lower():
        try:
            decoded = hostname.encode("ascii").decode("idna")
            return True, f"Punycode internationalized domain resolves to: {decoded}"
        except Exception:
            return True, "Punycode encoded domain"

    detected = []
    for char in hostname:
        if char in HOMOGLYPH_CHARS:
            detected.append(f"'{char}' (looks like '{HOMOGLYPH_CHARS[char]}')")

    if detected:
        return True, f"Confusable homoglyph characters detected: {', '.join(detected[:5])}"

    return False, ""


def check_misleading_subdomain(subdomain: str, domain: str) -> tuple[bool, str]:
    """
    Checks if a recognizable brand name appears in the subdomain while the
    registrable domain belongs to an unrelated third party.
    """
    if not subdomain or not domain:
        return False, ""

    sub_lower = subdomain.lower()
    dom_lower = domain.lower()

    for brand in POPULAR_BRANDS:
        if brand == dom_lower:
            continue

        if re.search(r"(?:^|[\.-])" + re.escape(brand) + r"(?:[\.-]|$)", sub_lower):
            return True, brand

    return False, ""


def check_executable_extension(path: str) -> tuple[bool, str]:
    """Checks if path ends with an executable or package file extension."""
    if not path:
        return False, ""

    clean_path = path.lower().split("?")[0].split("#")[0]
    for ext in EXECUTABLE_EXTENSIONS:
        if clean_path.endswith(ext):
            return True, ext

    return False, ""


def check_suspicious_encoding(raw_url: str) -> bool:
    """Detects double-URL encoding or obfuscated percent signs."""
    if re.search(r"%25[0-9a-fA-F]{2}", raw_url):
        return True
    return False


def parse_url_string(url_str: str) -> Optional[ParsedUrl]:
    """Parses a single URL string into a ParsedUrl structure with security metadata."""
    trimmed = url_str.strip()
    if not trimmed:
        return None

    # Check for dangerous non-web schemes directly
    for dangerous in DANGEROUS_SCHEMES:
        if trimmed.lower().startswith(f"{dangerous}:"):
            return ParsedUrl(
                raw_url=trimmed,
                scheme=dangerous,
                is_dangerous_scheme=True,
                dangerous_scheme_name=dangerous,
                hostname=dangerous,
                registrable_domain=dangerous,
            )

    has_explicit_scheme = "://" in trimmed
    full_url = trimmed if has_explicit_scheme else f"http://{trimmed}"

    try:
        parsed = urllib.parse.urlsplit(full_url)
    except Exception:
        return None

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc

    port = None
    try:
        port = parsed.port
    except ValueError:
        port = None

    hostname = ""
    try:
        hostname = parsed.hostname or ""
    except ValueError:
        hostname = netloc.split(":")[0] if netloc else ""

    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment

    has_at_symbol = "@" in netloc
    userinfo = ""
    if has_at_symbol:
        userinfo = netloc.split("@")[0]

    extracted = _offline_extractor(hostname)
    subdomain = extracted.subdomain
    domain = extracted.domain
    suffix = extracted.suffix
    registrable_domain = f"{domain}.{suffix}" if domain and suffix else (domain or hostname)

    ip_check = is_ip_address(hostname)
    shortener_check = registrable_domain.lower() in SHORTENER_DOMAINS or hostname.lower() in SHORTENER_DOMAINS
    tld_check = suffix.lower() in SUSPICIOUS_TLDS
    homoglyph_check, homoglyph_desc = check_homoglyphs(hostname)
    misleading_check, brand_match = check_misleading_subdomain(subdomain, domain)
    exec_check, exec_ext = check_executable_extension(path)
    encoding_check = check_suspicious_encoding(trimmed)

    return ParsedUrl(
        raw_url=trimmed,
        scheme=scheme,
        netloc=netloc,
        hostname=hostname,
        port=port,
        path=path,
        query=query,
        fragment=fragment,
        userinfo=userinfo,
        subdomain=subdomain,
        domain=domain,
        suffix=suffix,
        registrable_domain=registrable_domain,
        is_ip=ip_check,
        is_shortener=shortener_check,
        has_suspicious_tld=tld_check,
        has_homoglyphs=homoglyph_check,
        homoglyph_details=homoglyph_desc,
        has_embedded_credentials=has_at_symbol,
        has_executable_extension=exec_check,
        executable_ext=exec_ext,
        misleading_subdomain=misleading_check,
        impersonated_brand=brand_match,
        has_suspicious_encoding=encoding_check,
        has_at_symbol=has_at_symbol,
        is_dangerous_scheme=False,
    )


URL_REGEX = re.compile(
    r"(?i)\b(?:https?://|ftp://|www\.)[^\s<>\"]+"
    r"|(?:https?://)?(?:[a-zA-Z0-9_\-\u0400-\u04FF\u0370-\u03FF]+\.)+[a-zA-Z]{2,24}(?::\d{1,5})?(?:/[^\s<>\"]*)?"
    r"|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:/[^\s<>\"]*)?"
)


def extract_urls_from_text(text: str) -> List[str]:
    """Extracts all distinct URLs and web references from arbitrary text."""
    if not text:
        return []

    # Also detect dangerous schemes like javascript:, data:, file:
    dangerous_matches = re.findall(r"(?i)\b(?:javascript|data|file|vbscript):[^\s<>\"']+", text)

    urls = []
    seen = set()

    for item in dangerous_matches:
        cleaned_item = item.strip()
        if cleaned_item and cleaned_item not in seen:
            seen.add(cleaned_item)
            urls.append(cleaned_item)

    trailing_punct = ".,;!?:\"'()[]{}<>"
    for match in URL_REGEX.finditer(text):
        start = match.start()
        raw = match.group(0).rstrip(trailing_punct)
        if not raw:
            continue

        raw_lower = raw.lower()
        has_scheme = raw_lower.startswith(("http://", "https://", "ftp://"))
        is_www = raw_lower.startswith("www.")

        # Post-filter scheme-less matches (Finding 5)
        if not has_scheme and not is_www:
            # 1. Skip matches preceded by @ (e.g. user@example.com)
            if start > 0 and text[start - 1] == "@":
                continue

            # Check if match is an IP address
            clean_ip = raw.split("/")[0].split(":")[0].strip("[]")
            is_ip = is_ip_address(clean_ip)

            if not is_ip:
                host_part = raw.split("/")[0].split(":")[0].split("?")[0].split("#")[0]

                # 2. Skip a Title-case suffix label that directly follows a sentence-ending period (e.g. "end.Next", "Mr.Smith")
                # Do NOT drop all-caps domains like "HDFC-UPDATE.COM"
                if re.search(r"\b[a-zA-Z0-9_\-]+\.[A-Z][a-z]+$", host_part):
                    continue

                # 3. Require a known public suffix (via offline tldextract)
                ext = _offline_extractor(host_part)
                if not ext.suffix:
                    continue

        if raw not in seen:
            seen.add(raw)
            urls.append(raw)

    return urls
