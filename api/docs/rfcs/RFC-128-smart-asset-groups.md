# RFC-128: Smart asset groups

| | |
|---|---|
| Status | Accepted (2026-10-26). API and web editor shipped together ([smart-asset-groups.md](../architecture/smart-asset-groups.md) says what is shipped) |
| Scope | api (`pkg/domain/assetgroup`, `internal/app/asset`, `internal/infra/postgres`, asset group routes, migration `003440_smart_asset_groups`), web (asset group wizard and page, Assets list bulk actions) |
| Architecture | [smart-asset-groups.md](../architecture/smart-asset-groups.md), [asset-group-recalculation.md](../architecture/asset-group-recalculation.md) |
| Related | RFC-054 (scope), RFC-065 (programs), the data-scope model (`datascope`) |

## 1. Summary

Putting every subdomain of a company into a group means ticking hundreds of rows, and the group is stale the moment
discovery finds a new name. A group can now fill itself: a rule, a pasted list, a hand-picked set, or all three.

## 2. Use cases

| ID | Need | Example |
|---|---|---|
| U1 | Everything under a domain, kept up to date | `*.example.com`: the apex, its subdomains, their hosts, services, URLs and certificates |
| U2 | Everything a scope entry covers | the assets authorized by one scope entry |
| U3 | A filter | web applications tagged `prod`; assets using a technology; internet-exposed and criticality at least high; an address range |
| U4 | Turn what I see into a group | on the Assets list: "Save filter as group", "Add all N matching" |
| U5 | Paste a list | 200 host names from a spreadsheet; optionally create the missing ones through the scope check |
| U6 | Mostly automatic, with exceptions | a rule, always include a few, never include a few |
| U7 | Bring the children | services, URLs and certificates of the matched hosts |
| U8 | A hand-picked group | a small curated set, as before |

## 3. Decisions

| ID | Decision |
|---|---|
| D1 | A group's membership is the rule's matches plus the manual includes (picked or pasted) minus the manual excludes, **materialised** in `asset_group_members` with a `source` (`rule`, `manual`, `paste`), so scans, team scope rules, dashboards, SLAs and reports read members unchanged. Excludes win. |
| D2 | Rules reuse the Assets list filter model (same parameter names, same validation, same compiler) plus a domain condition with subdomains (label-boundary safe, punycode, wildcard accepted), covered-by-scope-entry and include-related. No new query language. |
| D3 | A rule is evaluated as its editor, inside the editor's data scope at evaluation time. An editor who left pauses the rule instead of emptying the group. Widening a group that team scope rules or scans use is audited and returned as an impact summary; for a team holding a privileged role it needs the owner and a recent sign-in. |
| D4 | A pasted list creates the missing assets only through the scope check; a name outside the scope becomes a candidate, as in an import. |

## 4. Design

See the architecture document for the rule document, evaluation triggers (save, asset change, hourly), preview, paste
and the access rules. The migration adds `rule`, `rule_editor_id`, `rule_status` and `rule_evaluated_at` to
`asset_groups`, `source` to `asset_group_members` (existing members become `manual`), `asset_group_exclusions` and
`asset_group_member_history`. It is safe on populated tables: new columns have defaults and no table is rewritten.

## 5. Threat model

| Threat | Control |
|---|---|
| A member builds a group that pulls in assets outside their data scope | the rule is compiled with the editor's data scope; preview, paste and "add all matching" use the caller's |
| A lookalike domain joins a domain rule | label-boundary match on `.<name>`, punycode, LIKE metacharacters escaped; tested |
| A pasted list reveals or reaches assets the caller cannot see | such names count as missing and are never created (the duplicate is refused) |
| A pasted list injects control characters, `javascript:` URLs, credentials, huge ranges | strict line parser, rejected with a reason, size caps (10,000 lines, 1,000 creations, /8 and /32 range floors) |
| A rule widens access of a team or a scan unnoticed | audit event `asset_group.rule_widened` and the impact summary before save; owner and step-up for privileged teams |
| A cross-tenant id in a rule or a membership change | every statement names the tenant; foreign assets are dropped; other tenants' groups answer 404 |
| A rule grows without bound | 50,000 member cap; over-cap leaves members unchanged and shows the state |
| An editor who left keeps a rule running with their old access | the rule pauses when the editor is not an active member |
