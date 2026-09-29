from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import func, select, text

from app.feeds.base import utcnow
from app.models import IOC, Observation, ProviderState
from app.normalization import normalize_domain, normalize_ip
from app.schemas import IOCOut, IOCPage, UpdateOut
from app.services.blocklist import describe, domains_text, ioc_query

router = APIRouter()
# Future authentication dependencies belong on this router (list consumption can stay separate).
api = APIRouter(prefix="/api")


@router.get("/health")
def health(request: Request):
    try:
        with request.app.state.db.session() as session:
            session.execute(text("SELECT 1"))
    except Exception:
        return JSONResponse({"status": "unhealthy", "database": "unavailable"}, status_code=503)
    return {"status": "ok", "database": "ok"}


@router.get("/lists/domains.txt", response_class=PlainTextResponse)
def domains(request: Request):
    return PlainTextResponse(
        domains_text(request.app.state.db, request.app.state.policy),
        headers={"Cache-Control": "no-store"},
    )


@api.get("/stats")
def stats(request: Request):
    state = request.app.state
    now = utcnow()
    total = active = blocked = ips = 0
    with state.db.session() as session:
        for ioc in session.scalars(ioc_query()).yield_per(500):
            decision = state.policy.evaluate(ioc, now)
            total += 1
            active += int(decision.active)
            blocked += int(decision.blocked)
            ips += int(ioc.ioc_type in ("ipv4", "ipv6"))
        source_counts = dict(
            session.execute(
                select(Observation.source, func.count(func.distinct(Observation.ioc_id))).group_by(
                    Observation.source
                )
            ).all()
        )
        provider_states = {p.source: p for p in session.scalars(select(ProviderState))}
        sources = {}
        for name in ("urlhaus", "threatfox"):
            p = provider_states.get(name)
            sources[name] = {
                "enabled": getattr(state.settings.providers, name).enabled,
                "ioc_count": source_counts.get(name, 0),
                "last_attempt": p.last_attempt if p else None,
                "last_success": p.last_success if p else None,
                "last_failure": p.last_failure if p else None,
                "last_error": p.last_error if p else None,
                "next_allowed_at": p.next_allowed_at if p else None,
                "last_success_counts": p.counts if p else {},
            }
    return {
        "total_iocs": total,
        "active_iocs": active,
        "blocked_domains": blocked,
        "tracked_ips": ips,
        "sources": sources,
        "update_running": state.updates.running,
        "last_update": state.updates.last_result,
    }


@api.get("/iocs", response_model=IOCPage)
def list_iocs(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    ioc_type: Literal["domain", "hostname", "ipv4", "ipv6"] | None = None,
):
    query = ioc_query()
    count_query = select(func.count(IOC.id))
    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type)
        count_query = count_query.where(IOC.ioc_type == ioc_type)
    now = utcnow()
    with request.app.state.db.session() as session:
        total = session.scalar(count_query)
        rows = session.scalars(query.order_by(IOC.id).offset(offset).limit(limit))
        items = [describe(row, request.app.state.policy, now) for row in rows]
    return IOCPage(total=total, limit=limit, offset=offset, items=items)


@api.get("/iocs/{ioc}", response_model=IOCOut)
def lookup(ioc: str, request: Request):
    if len(ioc) > 1024:
        raise HTTPException(422, "invalid indicator")
    try:
        try:
            value, _ = normalize_ip(ioc)
        except ValueError:
            value = normalize_domain(ioc)
    except ValueError:
        raise HTTPException(422, "invalid indicator") from None
    with request.app.state.db.session() as session:
        row = session.scalar(ioc_query().where(IOC.normalized_value == value))
        if row is None:
            raise HTTPException(404, "indicator not found")
        return describe(row, request.app.state.policy, utcnow())


@api.post("/update", response_model=UpdateOut, status_code=202)
async def update(request: Request):
    if not request.app.state.updates.trigger():
        return JSONResponse(
            {"status": "already_running", "status_url": "/api/stats"}, status_code=409
        )
    return UpdateOut(status="accepted")
