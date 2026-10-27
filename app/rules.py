"""Rule definitions, weights, and keyword lists for Ziva. Tune detection here."""

from typing import Dict, List, Set

# ---- Verdict thresholds (score is 0-100) ----
SAFE_THRESHOLD = 24          # 0-24   -> Safe
SUSPICIOUS_THRESHOLD = 59    # 25-59  -> Suspicious, 60+ -> High Risk

# ---- Weights ----
WEIGHT_IP_ADDRESS = 40
WEIGHT_MISSING_HTTPS = 15
WEIGHT_AT_SYMBOL = 35
WEIGHT_EXCESSIVE_HYPHENS = 20
WEIGHT_EXCESSIVE_LENGTH = 10
WEIGHT_TOO_MANY_SUBDOMAINS = 15
WEIGHT_BRAND_IMPERSONATION = 45
WEIGHT_SUSPICIOUS_KEYWORD_EACH = 5
WEIGHT_SUSPICIOUS_KEYWORDS_CAP = 20
WEIGHT_SUSPICIOUS_TLD = 15
WEIGHT_PUNYCODE = 35
WEIGHT_URL_SHORTENER = 20
WEIGHT_NON_STANDARD_PORT = 10
WEIGHT_SPECIAL_CHARS = 5
WEIGHT_DOUBLE_SLASH_REDIRECT = 10

RULES_INFO: Dict[str, Dict] = {
    "ip_address": {
        "rule_id": "ip_address",
        "title": "Uses an IP address instead of a domain name",
        "severity": "high",
        "weight": WEIGHT_IP_ADDRESS,
        "explanation": "Legitimate services use domain names. Attackers use raw or encoded IP addresses "
                       "(including hex/decimal forms) to hide who owns the server.",
    },
    "missing_https": {
        "rule_id": "missing_https",
        "title": "Connection is not secured with HTTPS",
        "severity": "medium",
        "weight": WEIGHT_MISSING_HTTPS,
        "explanation": "Without HTTPS, data you type (like passwords) can be read or changed in transit. "
                       "Most modern login pages use HTTPS.",
    },
    "at_symbol": {
        "rule_id": "at_symbol",
        "title": "Contains an '@' symbol",
        "severity": "high",
        "weight": WEIGHT_AT_SYMBOL,
        "explanation": "Browsers ignore everything before the '@'. In google.com@evil.com the real "
                       "destination is evil.com, but the link looks like Google.",
    },
    "excessive_hyphens": {
        "rule_id": "excessive_hyphens",
        "title": "Excessive hyphens in the domain",
        "severity": "medium",
        "weight": WEIGHT_EXCESSIVE_HYPHENS,
        "explanation": "Long hyphenated names like paypal-verify-account-login.com are a classic way to "
                       "make a fake domain look official.",
    },
    "excessive_length": {
        "rule_id": "excessive_length",
        "title": "Unusually long URL or hostname",
        "severity": "low",
        "weight": WEIGHT_EXCESSIVE_LENGTH,
        "explanation": "Very long URLs can hide the real domain or push the suspicious part out of view.",
    },
    "too_many_subdomains": {
        "rule_id": "too_many_subdomains",
        "title": "Too many subdomain levels",
        "severity": "medium",
        "weight": WEIGHT_TOO_MANY_SUBDOMAINS,
        "explanation": "Attackers stack subdomains (paypal.com.secure.login.evil.xyz) so a trusted name "
                       "appears first. Always read the domain from right to left.",
    },
    "brand_impersonation": {
        "rule_id": "brand_impersonation",
        "title": "Brand impersonation",
        "severity": "high",
        "weight": WEIGHT_BRAND_IMPERSONATION,
        "explanation": "A well-known brand name appears in the URL, but the real domain is not the brand's.",
    },
    "suspicious_keywords": {
        "rule_id": "suspicious_keywords",
        "title": "Suspicious keywords",
        "severity": "low",
        "weight": WEIGHT_SUSPICIOUS_KEYWORD_EACH,
        "explanation": "Words like login, verify, or update are used to create urgency and lure you "
                       "into entering credentials.",
    },
    "suspicious_tld": {
        "rule_id": "suspicious_tld",
        "title": "High-risk top-level domain",
        "severity": "medium",
        "weight": WEIGHT_SUSPICIOUS_TLD,
        "explanation": "Some TLDs are cheap or free and are abused heavily for phishing campaigns.",
    },
    "punycode_homograph": {
        "rule_id": "punycode_homograph",
        "title": "Punycode / non-ASCII characters (homograph risk)",
        "severity": "high",
        "weight": WEIGHT_PUNYCODE,
        "explanation": "Look-alike characters from other alphabets (like Cyrillic 'а') can make a fake "
                       "domain look identical to a real one.",
    },
    "url_shortener": {
        "rule_id": "url_shortener",
        "title": "URL shortener hides the destination",
        "severity": "medium",
        "weight": WEIGHT_URL_SHORTENER,
        "explanation": "You cannot tell where a shortened link leads until you click it.",
    },
    "non_standard_port": {
        "rule_id": "non_standard_port",
        "title": "Non-standard port",
        "severity": "low",
        "weight": WEIGHT_NON_STANDARD_PORT,
        "explanation": "Normal websites use port 80 or 443. Unusual ports are common on throwaway attacker servers.",
    },
    "excessive_special_chars": {
        "rule_id": "excessive_special_chars",
        "title": "Excessive special or encoded characters in path",
        "severity": "low",
        "weight": WEIGHT_SPECIAL_CHARS,
        "explanation": "Heavy use of %xx encoding and symbols can be used to obfuscate the real target.",
    },
    "double_slash_redirect": {
        "rule_id": "double_slash_redirect",
        "title": "Embedded redirect or double slash",
        "severity": "low",
        "weight": WEIGHT_DOUBLE_SLASH_REDIRECT,
        "explanation": "A second URL hidden inside the link may bounce you to a different, malicious site.",
    },
}

SUSPICIOUS_KEYWORDS: List[str] = [
    "login", "verify", "secure", "update", "account",
    "confirm", "banking", "password", "signin", "wallet",
]

SUSPICIOUS_TLDS: Set[str] = {
    "zip", "mov", "xyz", "top", "tk", "click", "gq", "ml", "ga", "cf",
    "work", "support", "loan", "country", "kim", "men", "party", "review",
    "link", "rest", "buzz", "cyou", "icu", "monster",
}

URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
    "bl.ink", "lnkd.in",
}

# Two-part public suffixes so "bbc.co.uk" is parsed as domain "bbc.co.uk".
MULTI_PART_TLDS: Set[str] = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in", "ac.in",
    "gov.in", "co.jp", "com.au", "co.nz", "co.za", "com.br", "com.cn", "com.mx",
}

# brand keyword -> list of legitimate registered domains
KNOWN_BRANDS: Dict[str, List[str]] = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com"],
    "google": ["google.com", "google.co.in", "google.co.uk", "googleapis.com", "gstatic.com"],
    "microsoft": ["microsoft.com", "microsoftonline.com", "live.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "linkedin": ["linkedin.com"],
    "github": ["github.com", "github.io", "githubusercontent.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "ebay": ["ebay.com"],
    "paytm": ["paytm.com"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
}
