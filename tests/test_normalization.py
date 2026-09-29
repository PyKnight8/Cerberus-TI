import pytest

from app.normalization import (
    normalize,
    normalize_domain,
    normalize_ip,
    safe_indicator,
    url_indicator,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("  Evil.Example.  ", "evil.example"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("xn--bcher-kva.de", "xn--bcher-kva.de"),
        ("a-b.evil.example", "a-b.evil.example"),
    ],
)
def test_domains(value, expected):
    assert normalize_domain(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "localhost",
        "evil example.com",
        "evil\nexample.com",
        "https://evil.example/",
        "evil.example/path",
        "evil.example:80",
        "evil.example..",
        "-bad.example",
        "bad-.example",
        "a..example",
        "_srv.example",
        "*.example",
        "1.2.3.4",
        "127.1",
        "bad%20.example",
        "a" * 64 + ".example",
        "[::1]",
        "evil@example.com",
        "xn--.com",
    ],
)
def test_reject_invalid_domains(value):
    with pytest.raises(ValueError):
        normalize_domain(value)


@pytest.mark.parametrize(
    "value,expected,kind",
    [
        (" 8.8.8.8 ", "8.8.8.8", "ipv4"),
        ("2001:4860:4860:0000:0000:0000:0000:8888", "2001:4860:4860::8888", "ipv6"),
    ],
)
def test_ips(value, expected, kind):
    assert normalize_ip(value) == (expected, kind)


@pytest.mark.parametrize(
    "value", ["999.1.2.3", "192.168.001.1", "fe80::1%eth0", "::gg", "8.8.8.8:80"]
)
def test_invalid_ips(value):
    with pytest.raises(ValueError):
        normalize_ip(value)


def test_type_mismatch():
    with pytest.raises(ValueError):
        normalize("::1", "ipv4")


@pytest.mark.parametrize(
    "value,kind",
    [
        ("localhost", "hostname"),
        ("router.local", "hostname"),
        ("host.home.arpa", "domain"),
        ("host.internal", "domain"),
        ("host.lan", "domain"),
        ("127.0.0.1", "ipv4"),
        ("10.0.0.1", "ipv4"),
        ("192.168.1.1", "ipv4"),
        ("172.16.0.1", "ipv4"),
        ("169.254.1.1", "ipv4"),
        ("224.0.0.1", "ipv4"),
        ("0.0.0.0", "ipv4"),
        ("::1", "ipv6"),
        ("::", "ipv6"),
        ("fe80::1", "ipv6"),
        ("ff02::1", "ipv6"),
        ("fc00::1", "ipv6"),
        ("::ffff:192.168.1.1", "ipv6"),
        ("100.64.0.1", "ipv4"),
    ],
)
def test_safety_exclusions(value, kind):
    assert not safe_indicator(value, kind)


def test_url_extracts_host_only():
    assert url_indicator("https://Evil.Example.:443/file.exe?a=1") == ("evil.example", "hostname")
    assert url_indicator("https://[2001:4860::1]/file") == ("2001:4860::1", "ipv6")


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "http://",
        "https://u:p@evil.example/",
        "http://evil.example:99999/",
        "http://evil.example\n/path",
    ],
)
def test_invalid_url(url):
    with pytest.raises(ValueError):
        url_indicator(url)
