# AGENTS.md

## Project

Cerberus-TI is a self-hosted threat-intelligence aggregation and enforcement service for a homelab.

Primary goals:

- ingest threat intelligence from trusted providers
- normalize and correlate IOCs
- maintain historical IOC/source observations
- generate DNS blocklists for Pi-hole
- later generate a conservative malicious-IP feed for MikroTik
- provide a FastAPI management dashboard

Cerberus-TI is the threat-intelligence authority.
Pi-hole and MikroTik are enforcement consumers.

## Technology

Use:

- Python 3.12+
- FastAPI
- SQLAlchemy
- SQLite
- Pydantic
- httpx
- Jinja2
- pytest
- Docker / Docker Compose

Do not introduce Flask.

Avoid unnecessary frontend frameworks.

## Architecture

Preserve the existing modular architecture.

Important areas include:

- app/feeds/        threat-intelligence providers
- app/services/     ingestion and blocklist services
- app/api/          JSON/API routes
- app/web.py        management UI
- app/templates/    HTML templates
- app/static/       local CSS/JS
- tests/            automated tests

Do not rewrite working subsystems unless necessary.

Prefer additive changes and small refactors.

## Security Requirements

Treat all provider data as untrusted.

Never:

- log API keys
- expose full API keys in HTML or JSON
- commit secrets
- embed provider credentials in source
- execute data received from intelligence feeds
- follow arbitrary IOC URLs
- expose the management interface publicly by default

Provider API keys stored by the application must remain encrypted at rest.

Maintain CSRF protection and administrator authentication.

Keep Jinja autoescaping enabled.

Do not use `|safe` on untrusted provider content.

## Configuration

Secrets belong in environment variables or the encrypted credential store.

Normal application configuration belongs in YAML/database-backed settings as currently implemented.

Do not silently overwrite a user's `.env`.

Environment provider keys must remain backward compatible.

## Pi-hole

`/lists/domains.txt` is a public/internal-consumer endpoint and must remain usable without dashboard authentication.

Do not directly modify Pi-hole's internal database.

Generated domain lists must:

- contain one hostname/domain per line
- be normalized
- be deduplicated
- be sorted
- exclude allowlisted indicators
- exclude expired indicators

## MikroTik

MikroTik integration is safety-sensitive because this router is core homelab infrastructure.

Do not implement RouterOS changes unless explicitly requested.

When implemented:

- Cerberus should remain the intelligence authority.
- MikroTik should consume only a curated enforcement list.
- Maximum IPv4 enforcement list size: 10,000 entries.
- The 10,000-entry limit must be enforced as a hard ceiling.
- Prefer temporary/timed RouterOS address-list entries.
- Prefer pull-based integration over giving Cerberus broad router admin credentials.
- Use one dedicated Cerberus address list.
- Avoid creating one firewall rule per IOC.
- Do not modify unrelated firewall, NAT, routing, DHCP, DNS, or interface configuration.
- Support dry-run/staged rollout before enforcement.

Never push more than the configured hard maximum, even if upstream feeds contain more indicators.

## Performance

Keep the application suitable for a small homelab server.

Avoid:

- loading entire IOC tables into memory
- unbounded log retention
- excessive dashboard polling
- unnecessary database writes
- heavyweight infrastructure for simple counters

Use pagination for IOC browsing.

SQLite is intentional unless a future requirement clearly exceeds it.

## Testing

Before finishing code changes, run the relevant tests.

Default validation:

```bash
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m compileall app