import csv
import io
import json

import httpx
import pytest

from app.config import HTTPConfig
from app.feeds.base import FeedError, utcnow
from app.feeds.threatfox import ThreatFoxProvider
from app.feeds.urlhaus import URLhausProvider


def tf_row(**kwargs):
    row = dict(
        id="123",
        ioc="evil.example",
        ioc_type="domain",
        confidence_level=90,
        first_seen=utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        last_seen=None,
        malware="win.demo",
        tags=["demo"],
    )
    row.update(kwargs)
    return row


def tf_body(*rows):
    return json.dumps({"query_status": "ok", "data": list(rows)}).encode()


def uh_body(status="online"):
    stamp = utcnow().strftime("%Y-%m-%d %H:%M:%S")
    stream = io.StringIO()
    stream.write("# URLhaus CSV export\n")
    csv.writer(stream).writerow(
        [
            "123",
            stamp,
            "https://Evil.Example/payload.exe",
            status,
            stamp,
            "malware_download",
            "exe,botnet",
            "https://urlhaus.abuse.ch/url/123/",
            "tester",
        ]
    )
    return stream.getvalue().encode()


def test_urlhaus_csv():
    parsed = URLhausProvider("fake-key", HTTPConfig()).parse(uh_body())
    row = parsed.candidates[0]
    assert row.value == "evil.example" and row.ioc_type == "hostname"
    assert row.confidence is None and row.active
    assert row.tags == ["exe", "botnet"]
    assert row.metadata["url"].endswith("payload.exe")


def test_threatfox_types_metadata_and_malformed_records():
    rows = [
        tf_row(),
        tf_row(ioc="8.8.8.8:443", ioc_type="ip:port"),
        tf_row(ioc="[2001:4860::1]:443", ioc_type="ip:port"),
        tf_row(ioc="https://Evil.Example/payload", ioc_type="url"),
        tf_row(ioc_type="sha256_hash"),
        tf_row(confidence_level=101),
        None,
        tf_row(ioc="8.8.8.8:99999", ioc_type="ip:port"),
    ]
    parsed = ThreatFoxProvider("fake-key", HTTPConfig()).parse(tf_body(*rows))
    assert (parsed.fetched, parsed.rejected, parsed.ignored) == (8, 3, 1)
    assert [r.ioc_type for r in parsed.candidates] == ["domain", "ipv4", "ipv6", "hostname"]
    assert parsed.candidates[1].metadata["port"] == 443
    assert parsed.candidates[0].malware_family == "win.demo"


@pytest.mark.parametrize(
    "body",
    [b"<html>login</html>", b"not json", b"[]", b'{"query_status":"bad_auth","data":"secret"}'],
)
def test_malformed_response(body):
    with pytest.raises(FeedError):
        ThreatFoxProvider("fake-key", HTTPConfig()).parse(body)


@pytest.mark.parametrize("body", [b"<html>login</html>", b"", b"not,csv", b"# changed format"])
def test_invalid_csv(body):
    with pytest.raises(FeedError):
        URLhausProvider("fake-key", HTTPConfig()).parse(body)


async def test_endpoints_and_auth_are_fixed():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=b"data")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await URLhausProvider("fake/key", HTTPConfig()).fetch(client)
        await ThreatFoxProvider("fake-key", HTTPConfig()).fetch(client)
    assert seen[0].url.host == "urlhaus-api.abuse.ch"
    assert seen[0].url.raw_path.endswith(b"fake%2Fkey/recent.csv")
    assert seen[1].headers["Auth-Key"] == "fake-key"
    assert json.loads(seen[1].content) == {"query": "get_iocs", "days": 7}


@pytest.mark.parametrize(
    "status,code",
    [
        (401, "http_error_401"),
        (500, "http_error_500"),
        (302, "http_error_302"),
        (429, "rate_limited"),
    ],
)
async def test_http_errors(status, code):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(status, headers={"Retry-After": "600"})
        )
    ) as client:
        with pytest.raises(FeedError) as exc:
            await ThreatFoxProvider("secret", HTTPConfig()).fetch(client)
    assert exc.value.code == code
    assert "secret" not in str(exc.value)
    if status == 429:
        assert exc.value.retry_seconds == 600


async def test_timeout():
    def handler(request):
        raise httpx.ReadTimeout("SECRET_URL")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(FeedError, match="^timeout$"):
            await ThreatFoxProvider("key", HTTPConfig()).fetch(client)


async def test_response_size_limit():
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * 2048))
    ) as client:
        with pytest.raises(FeedError, match="response_too_large"):
            await ThreatFoxProvider("key", HTTPConfig(max_response_bytes=1024)).fetch(client)


async def test_missing_key_no_request():
    def fail(request):
        pytest.fail("must not make HTTP requests without keys")

    async with httpx.AsyncClient(transport=httpx.MockTransport(fail)) as client:
        with pytest.raises(FeedError, match="missing_api_key"):
            await URLhausProvider("", HTTPConfig()).fetch(client)
