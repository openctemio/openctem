### Security: every CI trust audience names the organization

- GitHub and GitLab trust configurations now require an audience that contains the organization id, as Bitbucket, CircleCI and Jenkins already did. The default is `openctem:tenant:<id>`. A token minted for one organization is then useless to any other.
- Behaviour change: existing GitHub and GitLab configurations with another audience are moved to the default by migration `ci_tenant_bound_audience`.
- For 90 days, a pipeline that existed before the migration may still request the old audience, until it requests the new one once. A new pipeline must use the new audience.
- Otherwise the exchange is refused with `legacy_audience`. The trust card shows the old audience and its end date. Update pipelines to the current snippet.
