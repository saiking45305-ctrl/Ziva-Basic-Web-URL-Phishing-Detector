"""Pure static analysis detection engine for Ziva. Zero I/O, zero network requests."""

from dataclasses import dataclass
import ipaddress
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.parse

from app.rules import (
    KNOWN_BRANDS, MULTI_PART_TLDS, RULES_INFO, SAFE_THRESHOLD,
    SUSPICIOUS_KEYWORDS, SUSPICIOUS_THRESHOLD, SUSPICIOUS_TLDS,
    URL_SHORTENERS, WEIGHT_BRAND_IMPERSONATION, WEIGHT_SUSPICIOUS_KEYWORD_EACH,
    WEIGHT_SUSPICIOUS_KEYWORDS_CAP,
)

CONFUSABLE_MAP: Dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ν": "v"
}

LURE_AFFIXES: Set[str] = {
    "id", "login", "signin", "verify", "account", "secure", "security",
    "update", "auth", "support", "service", "billing", "pay", "my"
}

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    explanation: str
    weight: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "explanation": self.explanation,
        }

@dataclass
class ParsedURL:
    scheme: str
    hostname: str
    registered_domain: str
    subdomains: List[str]
    path: str
    port: Optional[int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scheme": self.scheme,
            "hostname": self.hostname,
            "registered_domain": self.registered_domain,
            "subdomains": self.subdomains,
            "path": self.path,
            "port": self.port,
        }

@dataclass
class AnalysisResult:
    url: str
    normalized_url: str
    defanged_url: str
    score: int
    verdict: str
    findings: List[Finding]
    parsed: ParsedURL

def is_ip_address(host: str) -> bool:
    if not host:
        return False
    clean = host.strip("[]").strip()
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        pass
    if re.fullmatch(r"0x[0-9a-fA-F]{1,8}", clean, re.IGNORECASE):
        try:
            return 0 <= int(clean, 16) <= 0xFFFFFFFF
        except ValueError:
            pass
    if re.fullmatch(r"\d{1,10}", clean):
        try:
            return 0 <= int(clean, 10) <= 0xFFFFFFFF
        except ValueError:
            pass
    return False

def parse_domain_structure(hostname: str) -> Tuple[str, List[str], str]:
    if not hostname:
        return "", [], ""
    clean = hostname.lower().strip("[]").strip()
    if is_ip_address(clean):
        return clean, [], ""
    parts = clean.split(".")
    if len(parts) <= 1:
        return clean, [], ""
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in MULTI_PART_TLDS:
        return f"{parts[-3]}.{parts[-2]}.{parts[-1]}", parts[:-3], f"{parts[-2]}.{parts[-1]}"
    return f"{parts[-2]}.{parts[-1]}", parts[:-2], parts[-1]

def defang_url(url: str) -> str:
    defanged = url
    if defanged.startswith("https://"):
        defanged = "hxxps://" + defanged[8:]
    elif defanged.startswith("http://"):
        defanged = "hxxp://" + defanged[7:]
    return defanged.replace(".", "[.]")

def decode_homograph_representation(host: str) -> str:
    decoded = host
    if "xn--" in host.lower():
        try:
            decoded = host.encode("ascii").decode("idna")
        except Exception:
            decoded = host
    return "".join(CONFUSABLE_MAP.get(ch, ch) for ch in decoded.lower())

def _matches_brand_in_label(label: str, brand: str) -> bool:
    label = label.lower()
    brand = brand.lower()
    tokens = re.split(r"[-_.]+", label)
    if brand in tokens:
        return True
    if label.startswith(brand):
        rem = label[len(brand):]
        if rem.isdigit() or any(rem.startswith(aff) for aff in LURE_AFFIXES):
            return True
    if label.endswith(brand):
        prefix = label[:-len(brand)]
        if prefix.isdigit() or any(prefix.endswith(aff) for aff in LURE_AFFIXES):
            return True
    return False

def check_brand_impersonation(hostname: str, subdomains: List[str], registered_domain: str, userinfo: Optional[str] = None):
    host_lower = hostname.lower()
    reg_lower = registered_domain.lower()
    userinfo_lower = (userinfo or "").lower()

    decoded_host = decode_homograph_representation(host_lower)
    decoded_reg, decoded_subs, _ = parse_domain_structure(decoded_host)

    for brand, legit_domains in KNOWN_BRANDS.items():
        brand_in_sub = any(_matches_brand_in_label(sub, brand) for sub in (subdomains + decoded_subs))
        brand_in_reg = any(_matches_brand_in_label(t.split(".")[0], brand) for t in (reg_lower, decoded_reg) if t)
        brand_in_user = any(_matches_brand_in_label(tok, brand) for tok in re.split(r"[-_.:@]+", userinfo_lower)) if userinfo_lower else False

        if brand_in_sub or brand_in_reg or brand_in_user:
            is_legit = any(reg_lower == legit or reg_lower.endswith("." + legit) for legit in legit_domains)
            if not is_legit:
                return True, brand, f"Brand '{brand.capitalize()}' detected in URL, but the registered domain '{registered_domain}' does not belong to {brand.capitalize()}."
    return False, None, None

def analyze_url(raw_input_url: str) -> AnalysisResult:
    cleaned = raw_input_url.strip()
    if not cleaned:
        raise ValueError("URL cannot be empty.")
    if len(cleaned) > 2048:
        raise ValueError("URL exceeds maximum permitted length of 2048 characters.")

    has_explicit_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", cleaned))
    parse_target = cleaned if has_explicit_scheme else f"http://{cleaned}"
    split_res = urllib.parse.urlsplit(parse_target)

    raw_scheme = split_res.scheme.lower() if split_res.scheme else ""
    hostname = (split_res.hostname or "").lower()
    if not hostname and split_res.netloc:
        hostname = split_res.netloc.split("@")[-1].split(":")[0].lower()
    if not hostname:
        raise ValueError("Could not determine a valid hostname from the provided URL.")

    registered_domain, subdomains, tld = parse_domain_structure(hostname)
    path = split_res.path or "/"
    query = split_res.query
    userinfo = split_res.username or ("@" in split_res.netloc)

    findings: List[Finding] = []
    total_score: int = 0

    # 1. IP Address
    if is_ip_address(hostname):
        info = RULES_INFO["ip_address"]
        findings.append(Finding(info["rule_id"], info["title"], info["severity"], info["explanation"], info["weight"]))
        total_score += info["weight"]

    # 2. Missing HTTPS
    if not has_explicit_scheme or raw_scheme != "https":
        info = RULES_INFO["missing_https"]
        findings.append(Finding(info["rule_id"], info["title"], info["severity"], info["explanation"], info["weight"]))
        total_score += info["weight"]

    # 3. @ Symbol
    if userinfo or "@" in cleaned:
        info = RULES_INFO["at_symbol"]
        findings.append(Finding(info["rule_id"], info["title"], info["severity"], info["explanation"], info["weight"]))
        total_score += info["weight"]

    # 4. Excessive Hyphens
    clean_hyph = hostname.replace("xn--", "")
    if clean_hyph.count("-") >= 3:
        info = RULES_INFO["excessive_hyphens"]
        findings.append(Finding(info["rule_id"], f"{info['title']} ({clean_hyph.count('-')} found)", info["severity"], info["explanation"], info["weight"]))
        total_score += info["weight"]

    # 5. Length
    if len(cleaned) > 75 or len(hostname) > 30:
        info = RULES_INFO["excessive_length"]
        findings.append(Finding(info["rule_id"], info["title"], info["severity"], info["explanation"], info["weight"]))
        total_score += info["weight"]

    # 6. Deep Subdomains
    if len(subdomains) >= 3:
        info = RULES_INFO["too_many_subdomains"]
        findings.append(Finding(info["rule_id"], f"{info['title']} ({len(subdomains)} levels)", info["severity"], info["explanation"], info["weight"]))
        total_score += info["weight"]

    # 7. Brand Impersonation
    is_spoof, brand, detail = check_brand_impersonation(hostname, subdomains, registered_domain, split_res.username)
    if is_spoof and detail:
        info = RULES_INFO["brand_impersonation"]
        findings.append(Finding(info["rule_id"], f"Brand impersonation: {brand.capitalize()}", info["severity"], detail, WEIGHT_BRAND_IMPERSONATION))
        total_score += WEIGHT_BRAND_IMPERSONATION

    # 8. Keywords
    target_text = f"{hostname} {path} {query}".lower()
    matched = [kw for kw in SUSPICIOUS_KEYWORDS if re.search(r"(?:\b|[-_./?=&])" + re.escape(kw) + r"(?:\b|[-_./?=&]|\d)", target_text)]
    if matched:
        kw_weight = min(len(matched) * WEIGHT_SUSPICIOUS_KEYWORD_EACH, WEIGHT_SUSPICIOUS_KEYWORDS_CAP)
        info = RULES_INFO["suspicious_keywords"]
        findings.append(Finding(info["rule_id"], f"Suspicious keywords detected ({len(matched)})", info["severity"], info["explanation"], kw_weight))
        total_score += kw_weight

    # 9. Suspicious TLD
    tld_suffix = tld.split(".")[-1] if tld else ""
    if tld_suffix in SUSPICIOUS_TLDS:
        info = RULES_INFO["suspicious_tld"]
        findings.append(Finding(info["rule_id"], f"High-risk TLD (.{tld_suffix})", info["severity"], info["explanation"], info["weight"]))
        total_score += info["weight"]

    # 10. Punycode
    if "xn--" in hostname.lower() or any(ord(c) > 127 for c in hostname):
        info = RULES_INFO["punycode_homograph"]
        findings.append(Finding(info["rule_id"], info["title"], info["severity"], info["explanation"], info["weight"]))
        total_score += info["weight"]

    # 11. Shortener
    if registered_domain in URL_SHORTENERS or hostname in URL_SHORTENERS:
        info = RULES_INFO["url_shortener"]
        findings.append(Finding(info["rule_id"], info["title"], info["severity"], info["explanation"], info["weight"]))
        total_score += info["weight"]

    # 12. Non-Standard Port
    if split_res.port not in (80, 443, None):
        info = RULES_INFO["non_standard_port"]
        findings.append(Finding(info["rule_id"], f"Non-standard port ({split_res.port})", info["severity"], info["explanation"], info["weight"]))
        total_score += info["weight"]

    # 13. Special Chars
    if path.count("%") >= 3 or len(re.findall(r"[%@&;~$+]", path)) >= 4:
        info = RULES_INFO["excessive_special_chars"]
        findings.append(Finding(info["rule_id"], info["title"], info["severity"], info["explanation"], info["weight"]))
        total_score += info["weight"]

    # 14. Redirects
    if "//" in path or bool(re.search(r"(?:url|dest|target|redirect|next|r|goto)=(?:https?%3A%2F%2F|https?://|//)", query, re.IGNORECASE)):
        info = RULES_INFO["double_slash_redirect"]
        findings.append(Finding(info["rule_id"], info["title"], info["severity"], info["explanation"], info["weight"]))
        total_score += info["weight"]

    final_score = min(100, max(0, total_score))
    verdict = "Safe" if final_score <= SAFE_THRESHOLD else ("Suspicious" if final_score <= SUSPICIOUS_THRESHOLD else "High Risk")

    return AnalysisResult(
        url=cleaned,
        normalized_url=urllib.parse.urlunsplit((raw_scheme or "http", hostname, path, query, "")),
        defanged_url=defang_url(cleaned),
        score=final_score,
        verdict=verdict,
        findings=findings,
        parsed=ParsedURL(raw_scheme or "missing", hostname, registered_domain, subdomains, path, split_res.port),
    )
