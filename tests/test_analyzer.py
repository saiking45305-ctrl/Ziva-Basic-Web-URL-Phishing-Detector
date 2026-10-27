"""Automated pytest test suite for Ziva URL phishing detector."""

import pytest
from fastapi.testclient import TestClient

from app.analyzer import analyze_url, is_ip_address, parse_domain_structure, defang_url
from app.main import app

client = TestClient(app)


def rule_ids(res):
    return {f.rule_id for f in res.findings}


def test_legit_sites():
    for url in ("https://github.com", "https://www.wikipedia.org"):
        res = analyze_url(url)
        assert res.verdict == "Safe"
        assert res.score <= 24


def test_legit_brand_domain_not_flagged():
    res = analyze_url("https://www.paypal.com")
    assert "brand_impersonation" not in rule_ids(res)
    assert res.verdict == "Safe"


def test_ip_address():
    assert "ip_address" in rule_ids(analyze_url("http://192.168.1.1/admin"))


def test_hex_ip():
    assert "ip_address" in rule_ids(analyze_url("http://0xC0A80001/verify"))


def test_ipv6():
    assert is_ip_address("[::1]")


def test_at_symbol():
    res = analyze_url("https://google.com@evil.com")
    assert "at_symbol" in rule_ids(res)
    assert res.verdict == "High Risk"


def test_brand_impersonation():
    res = analyze_url("http://paypal.com.evil.xyz")
    assert "brand_impersonation" in rule_ids(res)
    assert res.verdict == "High Risk"


def test_punycode():
    assert "punycode_homograph" in rule_ids(analyze_url("https://xn--pypal-4ve.com"))


def test_hyphen_abuse():
    res = analyze_url("https://paypal-verify-account-login.example")
    assert "excessive_hyphens" in rule_ids(res)
    assert res.verdict == "High Risk"


def test_shortener_and_port():
    ids = rule_ids(analyze_url("https://bit.ly/abc"))
    assert "url_shortener" in ids
    assert "non_standard_port" in rule_ids(analyze_url("https://example.com:8443/"))


def test_missing_scheme_is_flagged():
    assert "missing_https" in rule_ids(analyze_url("example.com"))


def test_multi_part_tld():
    reg, subs, tld = parse_domain_structure("www.bbc.co.uk")
    assert reg == "bbc.co.uk" and subs == ["www"] and tld == "co.uk"


def test_defang():
    assert defang_url("https://evil.com") == "hxxps://evil[.]com"


@pytest.mark.parametrize("bad", ["", "   "])
def test_empty_input_raises(bad):
    with pytest.raises(ValueError):
        analyze_url(bad)


def test_too_long_raises():
    with pytest.raises(ValueError):
        analyze_url("https://a.com/" + "a" * 2100)


def test_api_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_api_analyze():
    response = client.post("/api/analyze", json={"url": "https://github.com"})
    assert response.status_code == 200
    assert response.json()["verdict"] == "Safe"


def test_api_validation_errors():
    assert client.post("/api/analyze", json={}).status_code == 422
    assert client.post("/api/analyze", json={"url": "   "}).status_code == 422
    assert client.post("/api/analyze", json={"url": "a" * 2049}).status_code == 422
