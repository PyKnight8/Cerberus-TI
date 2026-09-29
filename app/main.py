import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from app.api.routes import api, router
from app.config import Settings, load_settings
from app.database import Database
from app.feeds.threatfox import ThreatFoxProvider
from app.feeds.urlhaus import URLhausProvider
from app.policy import BlockingPolicy
from app.scheduler import create_scheduler
from app.services.ingestion import UpdateService


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
        providers = []
        if config.providers.urlhaus.enabled:
            providers.append(
                URLhausProvider(config.urlhaus_auth_key.get_secret_value(), config.http)
            )
        if config.providers.threatfox.enabled:
            providers.append(
                ThreatFoxProvider(
                    config.threatfox_auth_key.get_secret_value(),
                    config.http,
                    config.providers.threatfox.days,
                )
            )
        updates = UpdateService(db, config, providers, transport)
        application.state.settings = config
        application.state.db = db
        application.state.policy = BlockingPolicy(config)
        application.state.updates = updates
        scheduler = create_scheduler(updates, config)
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
    application.include_router(router)
    application.include_router(api)
    return application


app = create_app()
