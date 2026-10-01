import logging
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.routes import api, router
from app.config import Settings, load_settings
from app.database import Database
from app.feeds.registry import make_provider
from app.management import PROVIDERS, cipher, get_key, load_runtime_settings, sync_allowlist
from app.policy import BlockingPolicy
from app.scheduler import create_scheduler
from app.services.ingestion import UpdateService
from app.web import web


def create_app(
    settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        config = settings or load_settings()
        logging.basicConfig(
            level=config.logging.level, format="%(asctime)s %(levelname)s %(name)s %(message)s"
        )
        # URLhaus embeds its credential in the request URL. Never emit HTTP wire logs.
        for name in (
            "httpx",
            "httpcore",
            "httpcore.connection",
            "httpcore.http11",
            "httpcore.http2",
        ):
            logging.getLogger(name).disabled = True
        db = Database(config.database_url)
        db.initialize()
        load_runtime_settings(db, config)
        crypto = cipher()
        providers = [
            make_provider(name, get_key(db, config, name, crypto), config)
            for name in PROVIDERS
            if getattr(config.providers, name).enabled
        ]
        updates = UpdateService(db, config, providers, transport)
        for provider in providers:
            provider.account_request = updates.account_request
        application.state.settings = config
        application.state.db = db
        application.state.policy = BlockingPolicy(config)
        sync_allowlist(db, application.state.policy)
        application.state.updates = updates
        application.state.crypto = crypto
        application.state.sessions = {}
        from app.services.enrichment import EnrichmentService

        application.state.enrichment = EnrichmentService(application.state)
        scheduler = create_scheduler(updates, config)
        application.state.scheduler = scheduler
        if config.scheduler.enabled:
            scheduler.start()
        if config.scheduler.update_on_start:
            updates.trigger()
        try:
            yield
        finally:
            if scheduler.running:
                scheduler.shutdown(wait=False)
            await updates.close()
            db.engine.dispose()

    application = FastAPI(title="Cerberus-TI", version="0.1.0", lifespan=lifespan)

    @application.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/admin"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'none'; style-src 'self'; "
                "img-src 'self'; form-action 'self'; frame-ancestors 'none'"
            )
        return response

    application.include_router(router)
    application.include_router(api)
    application.include_router(web)
    application.mount("/admin/static", StaticFiles(directory=Path(__file__).parent / "static"))
    return application


app = create_app()
