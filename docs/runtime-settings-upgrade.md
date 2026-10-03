# Runtime settings compatibility

Startup normalizes recognized runtime settings in a transaction before creating
providers or the scheduler. No table rebuild or volume reset is needed. The schema
version remains 3 because table structure is unchanged; normalization runs on each
startup and updates only rows whose representation or validated value differs.

Repository history contains two commits. The initial milestone did not have
runtime settings. The dashboard release writes ordinary settings and timestamps
as `{"value": ...}`, but writes `otx.retrieval_state` as a bare dictionary containing
`retrieval` and optionally `subscribed_retry_after`. The old startup reader wrongly
indexes every row by `value`, including this provider state. Additive schema
initialization did not convert this representation.

All recognized settings now use `{"value": ...}`, including OTX retrieval state.
The OTX service and dashboard read the envelope and also accept the historical
bare dictionary. Known policy/configuration settings additionally accept valid
JSON scalars (strings, booleans, integers), although no scalar writer is present in
the available history. Pydantic validates settings with their normal bounds and
boolean parsing. Unknown names are ignored and preserved without interpretation.

Invalid recognized values generate a warning containing only the setting name.
The configured/default value is persisted in the canonical envelope. This replaces
only unrecoverable overrides; valid overrides and OTX state fields are preserved.
No credential, administrator, IOC, observation or enrichment rows are modified.

From the existing Compose project directory, keeping the same project name and
`.env` (including `CERBERUS_SECRET_KEY`):

```sh
docker compose build cerberus-ti
docker compose up -d --no-deps cerberus-ti
docker compose logs --tail=100 cerberus-ti
```

The existing `cerberus-data` volume remains mounted. Do not run `down -v`.
