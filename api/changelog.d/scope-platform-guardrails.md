### Security: platform guardrails on scope (public suffixes, deny list, CIDR caps, ownership proof)

- A scope target that is, or wildcards, a public suffix (`*.com.vn`, `com`,
  `*.github.io`), a government or military name (`*.gov.vn`, `*.mil`), a
  shared-provider apex as a wildcard root (`*.amazonaws.com`), the whole
  address space, a link-local or cloud metadata address, or a public range
  larger than `/16` (IPv4) or `/32` (IPv6) is refused (`PUBLIC_SUFFIX`,
  `DENY_LIST`, `CIDR_TOO_LARGE`; RFC-054 §8).
- Deny-listed targets are refused at dispatch on every path, even inside a
  tenant's own scope target.
- New operator setting `SCOPE_ACTIVE_PROOF` (`off`, `platform_sensors`,
  `all`): when an active probe needs a verified domain of the organization.
  Unset it is `platform_sensors` for a self-service (SaaS) install and `off`
  otherwise. Jobs reach platform sensors only for verified targets there;
  intrusive (T2) scans always need a verified domain.
- New operator settings `SCOPE_MAX_PUBLIC_CIDR_V4` (16),
  `SCOPE_MAX_PUBLIC_CIDR_V6` (32) and `SCOPE_DENY_EXTRA` (the platform's own
  names and ranges). None of these is a tenant setting.
- **Upgrade note:** existing scope targets are not changed. A deny-listed or
  oversized existing entry stops authorizing deny-listed targets at
  dispatch; review entries wider than the caps.
