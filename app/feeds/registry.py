from app.feeds.otx import OTXProvider
from app.feeds.threatfox import ThreatFoxProvider
from app.feeds.urlhaus import URLhausProvider
from app.feeds.virustotal import VirusTotalProvider


def make_provider(name, key, settings):
    config = (
        settings.enrichment if name == "virustotal" else getattr(settings.providers, name, None)
    )
    if name == "urlhaus":
        provider = URLhausProvider(key, settings.http)
    elif name == "threatfox":
        provider = ThreatFoxProvider(key, settings.http, config.days)
    elif name == "otx":
        provider = OTXProvider(
            key, settings.http, config.max_pages, config.page_size, config=config
        )
    elif name == "virustotal":
        provider = VirusTotalProvider(key, settings.http)
    else:
        raise ValueError("unknown provider")
    provider.timeouts = config.http
    return provider
