from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import Database
from app.feeds.base import utcnow
from app.models import IOC
from app.policy import BlockingPolicy
from app.schemas import IOCOut, SourceOut


def ioc_query():
    return select(IOC).options(selectinload(IOC.observations))


def describe(ioc: IOC, policy: BlockingPolicy, now: datetime) -> IOCOut:
    decision = policy.evaluate(ioc, now)
    return IOCOut(
        id=ioc.id,
        ioc=ioc.normalized_value,
        value=ioc.value,
        type=ioc.ioc_type,
        active=decision.active,
        blocked=decision.blocked,
        policy_reasons=decision.reasons,
        first_seen=ioc.first_seen,
        last_seen=ioc.last_seen,
        created_at=ioc.created_at,
        updated_at=ioc.updated_at,
        expires_at=max((o.expires_at for o in ioc.observations), default=None),
        sources=[
            SourceOut(
                name=o.source,
                external_id=o.external_id,
                reported_type=o.reported_type,
                confidence=o.confidence,
                first_seen=o.first_seen,
                last_seen=o.last_seen,
                fetched_at=o.fetched_at,
                expires_at=o.expires_at,
                active=policy.live(o, now),
                policy_reason=policy.evidence_reason(o, now),
                malware_family=o.malware_family,
                tags=o.tags,
                metadata=o.details,
            )
            for o in sorted(ioc.observations, key=lambda o: (o.source, o.external_id))
        ],
    )


def domains_text(db: Database, policy: BlockingPolicy) -> str:
    now = utcnow()
    with db.session() as session:
        query = (
            ioc_query()
            .where(IOC.ioc_type.in_(("domain", "hostname")))
            .order_by(IOC.normalized_value)
        )
        domains = [
            ioc.normalized_value
            for ioc in session.scalars(query).yield_per(500)
            if policy.evaluate(ioc, now).blocked
        ]
    return "\n".join(domains) + ("\n" if domains else "")
