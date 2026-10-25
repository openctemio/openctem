# Informational findings in the findings work views

Informational findings are stored with severity `info` or `none` (a CVSS 0.0
score, and the scanner templates that only detect a technology, a WAF or an
exposed API description). They carry no remediation obligation: no SLA by
default, priority P3 and no risk-score weight (`vulnerability.IsInformational`).
They stay visible and filterable everywhere; this page describes where they are
left out by default and how a severity filter treats the two stored values.

## One Informational bucket

`info` and `none` are one reporting bucket (`vulnerability.SeverityBucket`):

- Every by-severity count folds `none` into `info`.
- A severity filter that names `info` also matches `none`, on every path:
  - the list query contract: the `severity` field's `EnumExpand` in
    `vulnerability.FindingFields`, so `GET /findings`, `/findings/stats`,
    `/findings/groups`, `/findings/export`, the quick views, bulk actions by
    filter, saved views and the query language all match both;
  - the older `FindingFilter` paths (`ListFindings`, used by MCP tools, and the
    grouped view's legacy filter) and the vulnerability catalog filter, through
    `vulnerability.ExpandSeverityFilter`;
  - ticket creation policies already allowed `none` with `info`
    (`ticketpolicy.Policy.AllowedSeverities`).
- `informational=true|false` is the boolean form of the same bucket in the
  list query contract (`findings.severity IN ('info', 'none')`).

## Work views

The work views are the quick views a person works from: Active, My queue and
SLA breached. They leave informational findings out by default: their `params`
carry `informational=false`. Needs triage always does, whatever the
preference: an informational finding has no SLA and is P3, so it never waits
for triage. All findings, Closed, Pending approval, Accepted expiring, an
explicit `severity=info` and any API call that does not send `informational`
are unchanged.

A view's count and its list compile the same params in the same caller scope
(`CountQuickViews`), so the Triage count and the sidebar counts always equal
the list totals.

Who decides, first match wins:

1. The member's own preference, `findings_informational` in
   `PUT /api/v1/users/me/preferences` (`include`, `exclude`, or `default` to
   follow the organization). Stored in `users.preferences`.
2. The organization's default, `include_informational` in
   `GET/PATCH /api/v1/organization/settings/finding-views` (owner or
   administrator with `settings:read` / `settings:write`; the organization comes
   from the token; audited as a settings change; settings section
   `finding_views`).
3. Otherwise informational findings are left out.

`GET /findings/quick-views` returns the resolved choice as
`include_informational`, and each view that leaves informational findings out
carries `informational_hidden`: how many it leaves out (the same params with
`informational=true`, counted in the same statement). A failed read of the organization default falls back
to leaving them out (it shapes a view, never access) and is logged.

## Console

The findings page never hides silently: while the open list leaves
informational findings out, the filter bar shows "Informational hidden (N)"
with a Show action. N comes from the quick view's `informational_hidden` when
the list is exactly that view, else from one count request with the list's
filter and `informational=true`. Show applies to the current view only and offers to save
the choice as the member's preference. The "Hide informational" switch in the
filter panel reflects the same state.

## Security

The preference and the default only add `informational=false` to a compiled
filter: the tenant, the caller's data scope and the pentest membership rule
are applied as on every list read, so no choice widens what a caller sees. The
organization default is read and written only by owners and administrators
of that organization, under the token's tenant; a member's preference changes
only their own views.
