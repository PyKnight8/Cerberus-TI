from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.config import Settings
from app.services.ingestion import UpdateService


def create_scheduler(service: UpdateService, settings: Settings) -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler(timezone="UTC")

    async def scheduled_update():
        service.trigger()

    scheduler.add_job(
        scheduled_update,
        "interval",
        minutes=settings.scheduler.update_interval_minutes,
        id="feed_update",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=60,
    )
    return scheduler
