### Security: every upstream response read is bounded

- SCM clients (GitHub, GitLab, Bitbucket, Azure DevOps), the Jira and
  DefectDojo clients, OAuth/SSO token and user-info calls, the LLM providers
  and S3 template downloads read upstream bodies without a size limit, so one
  hostile or broken endpoint could exhaust the API's memory (RFC-049 F-12).
  They now read through `httpsec.ReadLimited` / `httpsec.DecodeJSON` (10 MiB
  for API responses, the existing limits elsewhere).
- Reads that were capped with a plain `io.LimitReader` (Jira, OIDC token
  exchange, the CTEM-ID feed, the EPSS and KEV feeds, SBOM import) truncated
  silently; an oversize body is now an error, so a cut-off EPSS CSV no longer
  imports a partial score set. Finding report imports and attachments are
  capped on the read as well as on the declared size.
- security-lint Rule 8 fails CI on `io.ReadAll(resp.Body)` or
  `json.NewDecoder(resp.Body)` in the API.
