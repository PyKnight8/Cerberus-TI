"""LAN management UI; all writes require an authenticated session and CSRF token."""

import json
from pathlib import Path
from urllib.parse import parse_qs, quote

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

from app.config import OTXBlockingPolicy
from app.feeds.base import FeedError, utcnow
from app.feeds.otx import sync_plan
from app.feeds.registry import make_provider
from app.management import (
    INTEGRATIONS,
    PROVIDERS,
    get_key,
    mask,
    new_session,
    record_event,
    runtime_setting_value,
    save_runtime_setting,
    set_key,
    sync_allowlist,
    verify_password,
)
from app.models import (
    IOC,
    AdminAccount,
    ManagedAllowlist,
    OperationalEvent,
    ProviderCredential,
    ProviderKeyCheck,
    ProviderState,
    ProviderUsage,
    RuntimeSetting,
)
from app.normalization import normalize_domain
from app.services.blocklist import describe, ioc_query

ROOT = Path(__file__).parent
templates = Jinja2Templates(directory=ROOT / "templates")
web = APIRouter()


def authenticated(request):
    token = request.cookies.get("cerberus_session", "")
    entry = request.app.state.sessions.get(token)
    if not entry:
        return False
    if entry[1] <= utcnow():
        request.app.state.sessions.pop(token, None)
        return False
    return True


def valid_csrf(request, value):
    entry = request.app.state.sessions.get(request.cookies.get("cerberus_session", ""))
    return bool(entry and value and __import__("hmac").compare_digest(entry[0], value))


def csrf(request):
    return request.app.state.sessions[request.cookies["cerberus_session"]][0]


def page(request, name, **context):
    if not authenticated(request):
        return RedirectResponse("/admin/login", status_code=303)
    return templates.TemplateResponse(
        request, "page.html", {"section": name, "csrf": csrf(request), **context}
    )


async def form_action(request):
    if not authenticated(request):
        raise HTTPException(401, "administrator login required")
    data = await read_form(request)
    if not valid_csrf(request, str(data.get("csrf", ""))):
        raise HTTPException(403, "invalid CSRF token")
    return data


async def read_form(request):
    if not request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
        raise HTTPException(415, "form encoding required")
    body = await request.body()
    if len(body) > 8192:
        raise HTTPException(413, "form too large")
    return {key: values[-1] for key, values in parse_qs(body.decode("utf-8")).items()}


def redirect(section, message="Saved"):
    path = f"/admin/{section}" if section else "/admin"
    return RedirectResponse(f"{path}?notice={quote(message)}", status_code=303)


@web.get("/admin/login", response_class=HTMLResponse)
def login_page(request: Request):
    if authenticated(request):
        return RedirectResponse("/admin", status_code=303)
    with request.app.state.db.session() as session:
        ready = session.get(AdminAccount, 1) is not None
    return templates.TemplateResponse(request, "login.html", {"ready": ready})


@web.post("/admin/login")
async def login(request: Request):
    data = await read_form(request)
    if not verify_password(request.app.state.db, str(data.get("password", ""))):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"ready": True, "error": "Invalid credentials"},
            status_code=401,
        )
    token, csrf_token, expiry = new_session()
    request.app.state.sessions[token] = (csrf_token, expiry)
    response = RedirectResponse("/admin", status_code=303)
    response.set_cookie(
        "cerberus_session",
        token,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        max_age=8 * 3600,
        path="/",
    )
    return response


@web.post("/admin/logout")
async def logout(request: Request):
    await form_action(request)
    request.app.state.sessions.pop(request.cookies.get("cerberus_session", ""), None)
    response = RedirectResponse("/admin/login", status_code=303)
    response.delete_cookie("cerberus_session", path="/")
    return response


@web.get("/admin")
def dashboard(request: Request):
    if not authenticated(request):
        return RedirectResponse("/admin/login", status_code=303)
    state = request.app.state
    with state.db.session() as session:
        total = session.scalar(select(func.count()).select_from(IOC)) or 0
        types = dict(
            session.execute(select(IOC.ioc_type, func.count()).group_by(IOC.ioc_type)).all()
        )
        sources = list(session.scalars(select(ProviderState)))
        last_global = max((s.last_attempt for s in sources if s.last_attempt), default=None)
        allowed = session.scalar(select(func.count()).select_from(ManagedAllowlist)) or 0
        active = blocked = 0
        now = utcnow()
        for ioc in session.scalars(ioc_query()).yield_per(500):
            decision = state.policy.evaluate(ioc, now)
            active += int(decision.active)
            blocked += int(decision.blocked)
    next_job = state.scheduler.get_job("feed_update") if state.scheduler.running else None
    return page(
        request,
        "Dashboard",
        total=total,
        active=active,
        blocked=blocked,
        types=types,
        sources=sources,
        allowed=allowed + len(state.settings.allowlist.domains),
        running=state.updates.running,
        result=state.updates.last_result,
        last_global=last_global,
        next_update=next_job.next_run_time if next_job else None,
        enabled=sum(getattr(state.settings.providers, p).enabled for p in PROVIDERS),
    )


@web.get("/admin/feeds")
def feeds(request: Request):
    if not authenticated(request):
        return RedirectResponse("/admin/login", status_code=303)
    state = request.app.state
    with state.db.session() as session:
        rows = {p.source: p for p in session.scalars(select(ProviderState))}
        checkpoint = session.get(RuntimeSetting, "otx.modified_since")
        retrieval = session.get(RuntimeSetting, "otx.retrieval_state")
        retrieval_state = dict(runtime_setting_value(retrieval, {}))
    since, mode = sync_plan(
        state.settings.providers.otx, checkpoint.value["value"] if checkpoint else None, utcnow()
    )
    items = []
    for name in PROVIDERS:
        items.append(
            {
                "name": name,
                "otx_retrieval": retrieval_state.get(
                    "retrieval",
                    "subscribed"
                    if state.settings.providers.otx.retrieval_strategy == "auto"
                    else state.settings.providers.otx.retrieval_strategy,
                ),
                "otx_endpoint_retry": retrieval_state.get("subscribed_retry_after"),
                "otx_mode": mode if name == "otx" else None,
                "otx_since": since if name == "otx" else None,
                "otx_config": state.settings.providers.otx if name == "otx" else None,
                "enabled": getattr(state.settings.providers, name).enabled,
                "configured": bool(get_key(state.db, state.settings, name, state.crypto)),
                "state": rows.get(name),
                "cooldown_until": state.updates.cooldown_until(name),
                "read_timeout": make_provider(name, "", state.settings).http_timeout().read,
                "diagnostics": rows[name].counts.get("last_failure_diagnostics", {})
                if name in rows
                else {},
            }
        )
    return page(request, "Feeds", feeds=items, running=state.updates.running)


@web.post("/admin/update")
async def update_all(request: Request):
    await form_action(request)
    if not request.app.state.updates.trigger():
        return redirect("", "Update already running")
    return redirect("", "Update started")


@web.post("/admin/feeds/{source}/update")
async def update_feed(source: str, request: Request):
    await form_action(request)
    if source not in PROVIDERS:
        raise HTTPException(404)
    if not request.app.state.updates.trigger(source):
        return redirect("feeds", request.app.state.updates.trigger_notice)
    return redirect("feeds", "Update started")


@web.post("/admin/feeds/{source}/toggle")
async def toggle_feed(source: str, request: Request):
    await form_action(request)
    if source not in PROVIDERS:
        raise HTTPException(404)
    state = request.app.state
    config = getattr(state.settings.providers, source)
    config.enabled = not config.enabled
    save_runtime_setting(state.db, f"provider.{source}.enabled", config.enabled)
    if config.enabled:
        key = get_key(state.db, state.settings, source, state.crypto)
        provider = make_provider(source, key, state.settings)
        state.updates.replace_provider(provider)
    else:
        state.updates.providers = [p for p in state.updates.providers if p.name != source]
    record_event(
        state.db, source, "INFO", "Provider enabled" if config.enabled else "Provider disabled"
    )
    return redirect("feeds")


@web.get("/admin/api-keys")
def api_keys(request: Request):
    if not authenticated(request):
        return RedirectResponse("/admin/login", status_code=303)
    state = request.app.state
    with state.db.session() as session:
        usage = {r.source: r for r in session.scalars(select(ProviderUsage))}
        checks = {r.source: r for r in session.scalars(select(ProviderKeyCheck))}
        managed = set(session.scalars(select(ProviderCredential.source)))
    items = [
        {
            "name": name,
            "kind": INTEGRATIONS[name],
            "managed": name in managed,
            "masked": mask(get_key(state.db, state.settings, name, state.crypto)),
            "usage": usage.get(name),
            "check": checks.get(name),
        }
        for name in INTEGRATIONS
    ]
    return page(request, "API Keys", keys=items)


@web.post("/admin/api-keys/{source}/test")
async def test_key(source: str, request: Request):
    await form_action(request)
    if source not in INTEGRATIONS:
        raise HTTPException(404)
    state = request.app.state
    key = get_key(state.db, state.settings, source, state.crypto)
    if not key:
        return redirect("api-keys", "No key configured")
    provider = make_provider(source, key, state.settings)
    provider.account_request = state.updates.account_request
    status = "valid"
    try:
        async with httpx.AsyncClient(
            timeout=state.settings.http.timeout_seconds,
            follow_redirects=False,
            trust_env=False,
            headers={"Accept-Encoding": "identity", "User-Agent": "Cerberus-TI/0.1"},
            transport=state.updates.transport,
        ) as client:
            body = await provider.fetch(client)
            provider.parse(body)
    except FeedError as exc:
        status = exc.code
    except Exception:
        status = "validation_failed"
    with state.db.session.begin() as session:
        row = session.get(ProviderKeyCheck, source)
        if row is None:
            row = ProviderKeyCheck(source=source)
            session.add(row)
        row.checked_at = utcnow()
        row.status = status
    record_event(state.db, source, "INFO" if status == "valid" else "WARNING", "Key test " + status)
    return redirect("api-keys", "Key test: " + status)


@web.post("/admin/api-keys/{source}")
async def save_key(source: str, request: Request):
    data = await form_action(request)
    if source not in INTEGRATIONS:
        raise HTTPException(404)
    state = request.app.state
    try:
        set_key(state.db, source, str(data.get("key", "")), state.crypto)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(400, str(exc)) from None
    key = get_key(state.db, state.settings, source, state.crypto)
    provider = make_provider(source, key, state.settings)
    if source in PROVIDERS and getattr(state.settings.providers, source).enabled:
        state.updates.replace_provider(provider)
    record_event(state.db, source, "INFO", "Provider key changed")
    return redirect("api-keys", "Key saved; next provider request uses it")


@web.post("/admin/api-keys/{source}/remove")
async def remove_key(source: str, request: Request):
    await form_action(request)
    if source not in INTEGRATIONS:
        raise HTTPException(404)
    state = request.app.state
    with state.db.session.begin() as session:
        row = session.get(ProviderCredential, source)
        if row:
            session.delete(row)
        if source == "otx":
            for setting_name in ("otx.modified_since", "otx.retrieval_state"):
                checkpoint = session.get(RuntimeSetting, setting_name)
                if checkpoint:
                    session.delete(checkpoint)
    key = get_key(state.db, state.settings, source, state.crypto)
    if source in PROVIDERS and getattr(state.settings.providers, source).enabled:
        provider = make_provider(source, key, state.settings)
        state.updates.replace_provider(provider)
    record_event(state.db, source, "INFO", "Provider managed key removed")
    return redirect("api-keys", "Managed key removed")


@web.get("/admin/iocs")
def iocs(request: Request, q: str = "", page_number: int = 1):
    if not authenticated(request):
        return RedirectResponse("/admin/login", status_code=303)
    q = q.strip()[:253]
    page_number = max(1, page_number)
    query = select(IOC)
    if q:
        query = query.where(IOC.normalized_value.contains(q.replace("%", "\\%"), autoescape=True))
    with request.app.state.db.session() as session:
        total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
        rows = list(
            session.scalars(query.order_by(IOC.id.desc()).offset((page_number - 1) * 50).limit(50))
        )
    return page(request, "IOCs", iocs=rows, q=q, page_number=page_number, total=total)


@web.get("/admin/iocs/{ioc_id}")
def ioc_detail(ioc_id: int, request: Request):
    if not authenticated(request):
        return RedirectResponse("/admin/login", status_code=303)
    with request.app.state.db.session() as session:
        row = session.scalar(ioc_query().where(IOC.id == ioc_id))
        if row is None:
            raise HTTPException(404)
        item = describe(row, request.app.state.policy, utcnow())
    cached = request.app.state.enrichment.cached(ioc_id)
    return page(
        request,
        "IOC Detail",
        item=item,
        metadata=json,
        ioc_id=ioc_id,
        vt=cached,
        vt_age=round((utcnow() - cached.queried_at).total_seconds() / 3600, 1) if cached else None,
        vt_stale=bool(cached and cached.expires_at <= utcnow()),
        vt_configured=bool(
            get_key(
                request.app.state.db,
                request.app.state.settings,
                "virustotal",
                request.app.state.crypto,
            )
        ),
    )


@web.get("/admin/allowlist")
def allowlist(request: Request):
    if not authenticated(request):
        return RedirectResponse("/admin/login", status_code=303)
    with request.app.state.db.session() as session:
        managed = list(session.scalars(select(ManagedAllowlist).order_by(ManagedAllowlist.domain)))
    return page(
        request, "Allowlist", managed=managed, static=request.app.state.settings.allowlist.domains
    )


@web.post("/admin/allowlist")
async def add_allowlist(request: Request):
    data = await form_action(request)
    try:
        domain = normalize_domain(str(data.get("domain", "")))
    except ValueError:
        raise HTTPException(422, "invalid domain") from None
    state = request.app.state
    with state.db.session.begin() as session:
        row = session.get(ManagedAllowlist, domain)
        if row is None:
            session.add(
                ManagedAllowlist(
                    domain=domain, note=str(data.get("note", ""))[:500], created_at=utcnow()
                )
            )
    sync_allowlist(state.db, state.policy)
    record_event(state.db, "allowlist", "INFO", "Managed entry added")
    return redirect("allowlist")


@web.post("/admin/allowlist/{domain}/remove")
async def remove_allowlist(domain: str, request: Request):
    await form_action(request)
    state = request.app.state
    with state.db.session.begin() as session:
        row = session.get(ManagedAllowlist, domain)
        if row:
            session.delete(row)
    sync_allowlist(state.db, state.policy)
    record_event(state.db, "allowlist", "INFO", "Managed entry removed")
    return redirect("allowlist")


@web.get("/admin/settings")
def settings(request: Request):
    return page(request, "Settings", config=request.app.state.settings)


@web.post("/admin/settings")
async def save_settings(request: Request):
    data = await form_action(request)
    state = request.app.state
    try:
        interval = int(data.get("interval", ""))
        ttl = int(data.get("cache_ttl_hours", state.settings.enrichment.cache_ttl_hours))
    except ValueError:
        raise HTTPException(422, "invalid interval") from None
    if not 5 <= interval <= 10080:
        raise HTTPException(422, "interval must be 5 to 10080 minutes")
    if not 1 <= ttl <= 720:
        raise HTTPException(422, "cache TTL must be 1 to 720 hours")
    state.settings.enrichment.cache_ttl_hours = ttl
    save_runtime_setting(state.db, "enrichment.cache_ttl_hours", ttl)
    enabled = data.get("enabled") == "on"
    state.settings.scheduler.update_interval_minutes = interval
    state.settings.scheduler.enabled = enabled
    save_runtime_setting(state.db, "scheduler.interval", interval)
    save_runtime_setting(state.db, "scheduler.enabled", enabled)
    scheduler = state.scheduler
    if not scheduler.running:
        scheduler.start()
    if enabled:
        scheduler.reschedule_job("feed_update", trigger="interval", minutes=interval)
        scheduler.resume_job("feed_update")
    else:
        scheduler.pause_job("feed_update")
    record_event(state.db, "scheduler", "INFO", "Scheduler settings changed")
    return redirect("settings")


@web.post("/admin/settings/otx")
async def save_otx_policy(request: Request):
    data = await form_action(request)
    try:
        age = int(data.get("max_age_days", ""))
    except ValueError:
        raise HTTPException(422, "OTX maximum age must be 1 to 365 days") from None
    if not 1 <= age <= 365:
        raise HTTPException(422, "OTX maximum age must be 1 to 365 days")
    policy = OTXBlockingPolicy(
        enabled=data.get("enabled") == "on",
        official_author_only=data.get("official_author_only") == "on",
        max_age_days=age,
    )
    state = request.app.state
    # Persist all three fields atomically before publishing the runtime policy.
    with state.db.session.begin() as session:
        for field, value in policy.model_dump().items():
            name = f"policy.otx.{field}"
            row = session.get(RuntimeSetting, name)
            if row is None:
                row = RuntimeSetting(name=name)
                session.add(row)
            row.value = {"value": value}
    state.settings.policy.otx = policy
    record_event(state.db, "policy", "INFO", "OTX DNS blocking policy changed")
    return redirect("settings")


@web.get("/admin/logs")
def logs(request: Request, level: str = "", component: str = "", page_number: int = 1):
    if not authenticated(request):
        return RedirectResponse("/admin/login", status_code=303)
    query = select(OperationalEvent)
    if level in ("INFO", "WARNING", "ERROR"):
        query = query.where(OperationalEvent.level == level)
    if component:
        query = query.where(OperationalEvent.component == component[:32])
    with request.app.state.db.session() as session:
        rows = list(
            session.scalars(
                query.order_by(OperationalEvent.id.desc())
                .offset((max(1, page_number) - 1) * 100)
                .limit(100)
            )
        )
    return page(
        request,
        "Logs",
        events=rows,
        level=level,
        component=component,
        page_number=max(1, page_number),
    )


@web.post("/admin/iocs/{ioc_id}/virustotal")
async def enrich_ioc(ioc_id: int, request: Request):
    data = await form_action(request)
    with request.app.state.db.session() as session:
        ioc = session.get(IOC, ioc_id)
        if ioc is None:
            raise HTTPException(404)
    message = await request.app.state.enrichment.query(ioc, refresh=data.get("refresh") == "yes")
    return redirect(f"iocs/{ioc_id}", message)
