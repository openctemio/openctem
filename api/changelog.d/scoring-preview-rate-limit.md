### Security: the scoring preview is rate limited per organization

- `POST /tenants/{tenant}/settings/risk-scoring/preview` is limited to 6 calls per minute per organization (per API replica), then answers 429 with `Retry-After`. The preview is a dry run over every asset and open finding of the organization, so a scripted or compromised admin session could otherwise use it to load the database.
