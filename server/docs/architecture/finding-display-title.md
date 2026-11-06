# Finding title and target

A finding's stored `title` names the issue ("CVE-2019-9516 in nginx 1.15.5").
One issue on two assets gives two findings with the same title, so a list or a
ticket that shows only the title reads as a duplicate. The stored title is
never changed: search, dedup, grouping and the groups API use it.

## Target

The target is where the finding is, as one short string
(`vulnerability.FindingTarget`, mirrored by `findingLocation()` in the web):

- the URL the finding was observed at, when its location is an `http(s)` URL;
- else the asset name with the finding's port (`10.20.30.41:443`,
  `[fe80::1]:22`); a name that already carries a port or is a URL keeps its own;
- else nothing. A file path is not a target (the asset is), so code findings
  read "<title> on <repository>".

## Lists (web)

Every list of findings renders a row with `FindingTitleCell`
(`web/src/features/findings/components/cells/finding-title-cell.tsx`): the
title, then the target as a muted line under it, cut in the middle so the end
of a URL stays visible, the full value in the tooltip and in the row's
accessible name. `finding-title-cell.test.tsx` lists the pages that must use it.
On the Findings page the target line replaces the Location column, which is now
off by default (still available under Display).

## One string: `display_title`

Where a finding is one string, the server computes
`display_title = "<title> on <target>"` (`vulnerability.DisplayTitle`): one line,
control and direction characters removed, at most 500 characters, the target
kept whole when the title is cut. It is used by:

| Place | Source |
| --- | --- |
| `GET /findings`, `GET /findings/{id}` | `display_title` on each finding |
| Findings export (CSV, JSON) | `display_title` column, after `title`; asset id, name and type stay their own columns |
| Jira issue summary, GitHub issue title | `[severity] <display title>`, then redacted, encoded and capped as before |
| Ticket field mapping | `finding.display_title` attribute (summary tier); the security bug and service desk presets use it |
| Approval requests, reminders and decision notices (in-app and e-mail) | the notice line names the target |
| MCP `list_findings`, `get_finding` | `display_title` on each finding |

## Security

- The asset name is read in the finding's own tenant (tenant-scoped repository
  reads); a failed or out-of-tenant lookup leaves the asset out, and the display
  title is the title alone.
- It adds nothing the reader could not already see: list and detail callers are
  data-scope checked before the asset lookup; approval notices go only to
  approvers and requesters the finding's data scope admits; MCP findings are read
  through the key owner's data scope, which admits their asset.
- A tracker receives a URL target only for a finding whose full content may
  leave (`ticketing.OutboundTarget`): a secret or data-exposure finding's URL can
  carry the value itself, so those name the asset and port only.
- All parts are scanner-supplied text: one line, no control or bidi characters;
  the tracker renderers redact secrets and encode markup as before.
