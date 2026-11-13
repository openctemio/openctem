# Smart asset groups

Asset groups that fill themselves: a rule, a pasted list, or a hand-picked set, in one group. Design:
[RFC-128](../rfcs/RFC-128-smart-asset-groups.md). Everything below is shipped unless it says otherwise.

## What a group holds

```
members = rule matches  +  manual includes (picked or pasted)  -  manual excludes
```

Members stay rows of `asset_group_members`, so scans, team scope rules, dashboards, SLAs and reports read them as
before. The new column `source` says how each came in:

| Source | Meaning | Survives a rule evaluation |
|---|---|---|
| `rule` | the rule matched it | only while the rule still matches |
| `manual` | picked, or added with "add all matching" | yes |
| `paste` | came in with a pasted list | yes |

An asset taken out of a group that has a rule is stored in `asset_group_exclusions` and never comes back through
the rule (excludes win). Adding it by hand again lifts the exclusion. Removing the rule turns the rule members into
manual ones and drops the exclusions.

## The rule

A versioned JSON document in `asset_groups.rule`:

```json
{
  "v": 1,
  "filter": { "types": ["domain"], "tags": ["prod"], "internet_facing": true },
  "domains": [{ "name": "example.com", "subdomains": true }],
  "covered_by": ["<scope entry id>"],
  "include_related": true
}
```

- `filter` takes the Assets list parameters of the same name (`types`, `statuses`, `criticalities`, `tags`,
  `tags_mode`, `exclude_tags`, `search`, `min_risk_score`, `has_findings`, `in_cidr`, `environments`,
  `technology`, `scope_status`, `attribution`, and so on). It is validated by the same input rules and compiled by
  the same filter compiler (`asset.BuildAssetFilter`), so what the Assets page shows is what the rule matches.
- `domains` match the name itself and, with `subdomains`, every name below it on a label boundary:
  `example.com` never matches `evilexample.com` or `example.com.evil.com`. Names are lowercased and converted to
  punycode; a leading `*.` is accepted and means the domain and everything below it. A URL, port, path, address or
  any other wildcard is refused.
- `covered_by` keeps the assets a scope entry confirmed (any of the listed entries).
- `include_related` adds the services, web endpoints, certificates and applications linked to the matched hosts
  (by parent, or by a `runs_on`, `exposes`, `serves_certificate` or `contains` relationship), within the editor's
  data scope.
- A rule needs at least one condition. Unknown fields are refused. A rule document is at most 64 KB, at most 20
  domains and 20 scope entries.

## Who the rule runs as

A rule is evaluated as the person who last saved it, inside the data scope that person holds at evaluation time.
A person cannot build a group that pulls in assets they cannot see, and a later change of their access is followed
by the next evaluation. If the editor is no longer an active member, the rule is **paused**: the members stay as
they were and the group shows the state. A result over the cap (50,000 members, counting manual ones) is **over
cap**: the members also stay. The preview warns before saving.

An API key has no data scope of its own, so it cannot set a rule.

## When it is evaluated

- At save: the rule is evaluated first and refused, with the group unchanged, when it cannot run.
- When assets are created or change (asset create and update, bulk status change, and every ingest report that
  created or updated assets): a debounced run per tenant (5 s, never two runs of one tenant at once, one repeat
  when a change arrived during a run).
- Every hour, for every tenant (`AssetGroupRulesController`), as the safety net.

Each run writes the difference in one transaction: members that no longer match leave, new matches join, each with
a history row (`joined` or `left`, with the reason `matches_rule`, `no_longer_matches`, `added_by_hand`,
`added_by_paste`, `removed_by_hand`) in `asset_group_member_history`.

## Preview

`POST /asset-groups/rule/preview` evaluates a rule as the caller without saving: the number of matches, the first
20, and, with `group_id`, how many assets would join and leave and which teams and scans use the group. The count
stops at the cap plus one.

## Pasted lists

`POST /asset-groups/{id}/assets/paste` takes one name, IP address, CIDR range or `http(s)` URL per line (at most
10,000 lines; blank lines and `#` lines are skipped). A line is a value of one kind or it is reported as rejected
with a reason: control characters, spaces, a scheme other than `http` or `https` (`javascript:`, `data:`, `ftp:`),
credentials in a URL, an invalid host, a range wider than /8 (IPv4) or /32 (IPv6). Values are matched to existing
assets of the tenant inside the caller's scope; an asset the caller cannot see counts as missing, so a list reveals
nothing about it. A range matches the address assets inside it and is never created.

With `create_missing` (needs the assets write permission) the missing names are created, at most 1,000 per paste,
through the scope check: a name the organization's scope covers joins the inventory; any other becomes a
**candidate** (out of the inventory, never probed or scanned until a person decides), exactly as an import does. Dry
runs report the same counts and change nothing.

## Add all matching

`POST /asset-groups/{id}/assets/matching` takes a rule document and adds every asset it matches inside the
caller's scope as manual members, not only the page the caller sees. The Assets page offers it as "Add all N
matching", and offers "Save filter as group" which creates a group with the filter as its rule.

## Access and impact

- Rules, previews, pastes and history are tenant-scoped in every statement; another tenant's group answers 404.
- A change that brings assets into a group that team scope rules or scans use (`widens`) is audited as
  `asset_group.rule_widened` (severity high) and returned as an impact summary: `would_join`, the teams and the
  scans that use the group.
- A group that a team holding a privileged role uses (full data access, member, team, role, key, secret or
  settings administration) is changed (rule, picked or pasted members, removal) only by the owner with a recent
  sign-in.
- A rule never authorises scanning. Scans on a group resolve the members when they run and still pass the scope
  gate, the exclusions and the proof rules.
- History shows a restricted reader only the assets in their scope.

## Key files

| Area | Files |
|---|---|
| Domain | `pkg/domain/assetgroup/rule.go`, `paste.go`, `rule_repository.go` |
| Service | `internal/app/asset/group_rule.go`, `group_rule_members.go`, `group_rule_scheduler.go` |
| Store | `internal/infra/postgres/asset_group_rule_repository.go`, migration `003440_smart_asset_groups` |
| API | `internal/infra/http/handler/asset_group_rule_handler.go`, routes in `routes/assets.go` |
| Safety net | `internal/infra/controller/asset_group_rules.go` |
