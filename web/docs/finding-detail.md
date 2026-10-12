# Finding detail: page and drawer

How `/findings/[id]` and the findings drawer are laid out, and why. The code is in
`src/app/(dashboard)/findings/[id]/page.tsx`,
`src/features/findings/components/detail/` and
`src/features/findings/components/finding-detail-drawer.tsx`.

## The job

A finding page has to answer five questions on the first screen, without scrolling
or switching tabs:

| Question                           | Where it is answered                                                                |
| ---------------------------------- | ----------------------------------------------------------------------------------- |
| What is it?                        | Header: type, CVE / CWE (linked), and the title, which wraps                        |
| How bad is it for **us**, and why? | "Why it matters": the P-class, the classifier's reason, and the signals behind it   |
| Where is it?                       | Properties rail: the asset with its type, criticality and exposure                  |
| How do I fix it?                   | "Fix": the one concrete action for this type of finding                             |
| Who owns it, and by when?          | Properties rail: status, severity, assignee, SLA due date with days left or overdue |

Everything else (description, code, request and response, identifiers, raw scanner
metadata) is one tab or one disclosure away; activity and comments are one click away
in the activity panel.

## Patterns this layout uses

- **The fix comes first**, with the fixed-in version and the one action that
  applies (upgrade, rotate, reconfigure); the other actions sit under "⋯".
- **Properties live in a right rail** (status, severity, assignee, tags, SLA);
  the narrative is in the main column. Empty fields are hidden.
- **The body is a fixed order of collapsible sections:** risk (CVSS, EPSS, KEV),
  remediation, details, evidence, related, activity. Rule help folds behind
  "Show more".
- **The pane differs by finding type:** code findings show the source-to-sink
  path next to the code; secrets show validity (Active / Inactive / Unknown)
  with a re-verify action and the token's metadata.
- **Priority factors are visible, not hover-only.** Global threat data is
  labelled as global, and attack paths and combined exposures are shown as the
  reason an issue matters.
- **A dismissal needs a reason**, and the reason goes into the timeline.

## Principles

1. **Answer first.** The header, then why it matters, then the fix. Properties go in
   a rail. Details go in tabs.
2. **Priority is about us, not the CVE.** Show the P-class with its reason and the
   signals that produced it. Group the signals:
   - exploitation: KEV, exploit maturity, EPSS
   - exposure: internet-facing, reachable from N entry points
   - business impact: asset criticality and exposure

   Each chip says whether it raises or lowers the priority (a coloured dot, plus
   hidden text for screen readers). Show only facts the data has; never invent
   "no exploit" when there is no advisory.

3. **One concrete fix, by type.** Lead with the action and its exact command. Put
   the full remediation plan one click away.
4. **The properties rail is the only place for state.** Status, severity, priority,
   assignee, SLA, asset, source, first and last seen, tickets, tags and ID each
   appear once. Rows without a value are hidden.
5. **Activity is a panel, not a tab and not a permanent column.** The old layout
   gave a third of the width to a feed with one entry; the Activity tab that
   replaced it grew into a long scroll once people commented. The rail now ends
   with an "Activity · N comments" summary that opens the shared ActivityPanel
   (`docs/ui/activity-panel.md`); `?tab=activity` links open it too.
6. **The page and the drawer share their parts,** so they cannot disagree:
   `toFindingDetail`, `useFindingTriage` (including the approval rule),
   `FindingWhyItMatters`, `FindingFixCard`, `FindingProperties` and
   `FindingActivity` (the activity summary and panel, also in the pentest sheet).
7. **No extra round trips.** `GET /findings/{id}` embeds the CVE record, the
   package and the asset context (api PR "the finding detail embeds its CVE record
   and affected package"). The priority score breakdown is fetched only when "How
   this was scored" is opened.
8. **House style.** Theme tokens only (the palette-drift gate). Monospace only for
   identifiers, versions, paths and code. Sentence case. A skeleton shaped like the
   page.

## Layout

```
Findings › CVE-2024-21538 · cross-spawn            (breadcrumb: CVE · package, not the raw ID)

[SCA] [CVE-2024-21538 ↗]                          ┌ Status    [New ▾]           ┐
cross-spawn ReDoS vulnerability                   │ Severity  [High (7.5) ▾]    │
[Re-verify] [AI triage] [⋯]                       │ Priority  P1                │
                                                  │ Assignee  [Unassigned ▾]    │
┌ ⚠ SLA overdue by 143 days ──────────────────┐   │ SLA due   May 12, 2026      │
└─────────────────────────────────────────────┘   │           143 days overdue  │
┌ Why it matters ─────────────────────────────┐   │ ───────────────────────     │
│ P1 Urgent · fix within 30 days               │   │ Asset     demo-web-storefront│
│ High severity, reachable, no compensating…   │   │           Web app · Critical │
│ Exploitation   Exposure          Impact      │   │ Found by  SCA · npm-audit    │
│ ● No known…    ● Internet-facing ● Critical  │   │ First seen May 7, 2026       │
│ ● EPSS 0.87%   ● Reachable from 1            │   │ Last seen  May 10, 2026      │
│ › How this was scored                        │   │ ID        dcdc3001… ⧉       │
└──────────────────────────────────────────────┘   └─────────────────────────────┘
┌ Fix ──────────────────────── Remediation plan┐     (sticky; 19rem; below lg it
│ Upgrade cross-spawn 7.0.3 → 7.0.5             │      sits above "Why it matters",
│ Transitive dependency · in package.json · npm │      with asset/dates folded)
│ "overrides": { "cross-spawn": "^7.0.5" }  ⧉   │
│ Also fixed in 6.0.6 (other release lines)     │   ┌ 💬 Activity · 3 comments ●  ┐
└──────────────────────────────────────────────┘   │ Jamie: patched in 7.0.5 · 2h│
Overview | Evidence | Remediation | Attack path | Related └─────────────────────────────┘
```

The tab is kept in the URL (`?tab=`). Attack path appears only when the finding has
a data flow.

## Type-aware parts

| Type              | Fix card                                                                                                                                                                                                                   | Overview section                                                                                    |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| SCA / container   | Upgrade _pkg_ _from_ → _to_, with a command for npm (an `overrides` block for a transitive dependency), yarn, pnpm, pip, go, cargo, gem, NuGet, Composer, Maven. Says "no fixed version yet" when the advisory lists none. | Affected package: package@version, fixed in, ecosystem, direct or transitive and its manifest, purl |
| Secret            | Revoke and rotate _service_, in four steps (revoke at the provider, reissue into a secret manager, purge history, review the access logs)                                                                                  | Exposed credential: type, service, validity, masked value, age, commits, expiry, scopes             |
| Misconfiguration  | Reconfigure _resource_: expected vs actual                                                                                                                                                                                 | Misconfigured resource: resource, policy, file, cause                                               |
| DAST              | The scanner's recommendation                                                                                                                                                                                               | Affected endpoint: method and URL, parameter; request and response in a disclosure                  |
| SAST and the rest | The recommendation plus the suggested fix code                                                                                                                                                                             | Code location: file:lines, branch and commit, the snippet, "View in repository"                     |
| Compliance / web3 | The recommendation                                                                                                                                                                                                         | Compliance control / smart contract fields                                                          |
| Pentest           | The analyst's guidance                                                                                                                                                                                                     | Markdown description, targets, and its own Pentest details tab                                      |

The fix rules live in `lib/fix-guidance.ts`, the signals in `lib/finding-signals.ts`;
both are unit-tested.

## Known gaps

- The type-specific fields are stored since #823 (columns) and #849 (the typed
  `type_details` document: a secret's 4+4 preview, fingerprint, scopes and
  rotation; a misconfiguration's policy name and cause). Findings stored before
  then show these sections from their next ingest. A secret value is never
  stored or returned: the preview has at most the first and last 4 characters.
- Upgrade commands cover the common ecosystems. An unknown ecosystem shows the
  version change without a command.
