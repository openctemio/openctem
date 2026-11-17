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
- **The Evidence tab shows every source.** Tool evidence, re-verify and validation
  results, the compliance controls card, code, attachments and uploaded files are
  always rendered when they exist; "No evidence" appears only when all of them are
  empty. The number on the tab counts all of them. Uploaded files are loaded through
  the API client; a failure shows a row with Retry instead of an empty section.
- **A request waiting on someone is visible where you are.** While a
  false-positive or accepted-risk request is pending, `FindingApprovalBand`
  (page and drawer) shows the requested status, who asked, when and why, whatever
  the finding's status is. The requester can cancel it there; approvers get a link
  to the approvals inbox, where the decision is made; everyone else reads it. The
  buttons are cosmetic: the API decides who may cancel or approve.
- **AI triage is opt-in and permission-aware.** The header button shows only to a
  user who may run it (`ai_triage:trigger`) in an organization that turned AI triage
  on (Settings > AI). Without `ai_triage:read` the page sends no AI triage request
  and shows no error. The "AI analysis" section on Overview is read from the finding's
  own AI triage endpoint (`/findings/{id}/ai-triage`), so it stays after newer
  comments and activity.

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
   Status, severity and assignee are locked by one helper, `isTriageLocked`, for
   findings people wrote (pentest, bug bounty, red team, manual), in the rail and in
   the drawer header. Undo of a status change asks for the note again when the
   previous status needs one.
7. **No extra round trips.** `GET /findings/{id}` embeds the CVE record, the
   package and the asset context (api PR "the finding detail embeds its CVE record
   and affected package"). The priority score breakdown is fetched only when "How
   this was scored" is opened.
8. **Honest states.** A missing or refused finding shows one "not found" copy (no
   way to tell the two apart), with no error toast and a single request: the
   activity and comment reads wait for the finding. A server or network error
   shows "could not load" with a Retry instead. A section whose read fails (the
   task band, ticket links, the retest check) shows an error row with Retry, never
   a blank or "—"; a 403/404 on a section keeps it hidden.
9. **House style.** Theme tokens only (the palette-drift gate). Monospace only for
   identifiers, versions, paths and code. Sentence case. A skeleton shaped like the
   page.

## Layout

The page is built from the detail kit (`docs/ui-style-contract.md`, "Detail pages").

```
Findings > CVE-2024-21538                          (top bar breadcrumb)

[Vulnerability] [CVE-2024-21538] [CWE-1333]                        <  2 of 27  >
cross-spawn ReDoS vulnerability          [...] [Re-verify] [AI triage] [main action]
Overview | Evidence 4 | Validation 2 | Remediation | Related | Details
------------------------------------------------------------------------------
[!] SLA overdue by 143 days                          Status     [New v]
                                                     Severity   [High (7.5) v]
Why it matters                                       Priority   P1
  P1 Urgent, fix within 30 days                      SLA due    May 12, 2026
  Exploitation   Exposure          Impact                       143 days overdue
  > How this was scored                              People
Fix                          Remediation plan        Assignee   [Unassigned v]
  Upgrade cross-spawn 7.0.3 to 7.0.5                 Watchers   2 watching  [bell]
Scanner output                                       ---------------------------
  > Show output                                      Asset      demo-web-storefront
Proof of fix                                         Found by   SCA, npm-audit
  Verification, Retest, Retest check                 First seen May 7, 2026
                                                     Tickets, Tags, ID
                                                     [ Activity, 3 comments  > ]
```

- **Header** (`FindingHeader` on `DetailPageHeader`): type and identifier chips, the place in the list the
  finding was opened from ("2 of 27" links back to that list; previous and next, also `k` and `j`), the title,
  one main action, two secondary ones (Re-verify, AI triage) and a More menu (Copy link, Copy finding ID,
  Add to task when it is not the main action, Create ticket, Mark as duplicate). Who found it is said once,
  in the properties.
- **Main action** (`FindingMainAction`), chosen by the finding's state; when the state's action is not
  available to the viewer, the next row applies:

  | State                              | Main action       | Gate (the same as elsewhere on the page)                                   |
  | ---------------------------------- | ----------------- | -------------------------------------------------------------------------- |
  | Duplicate of another finding       | Open the original | none (a link)                                                              |
  | Fix applied, and a retest can run  | Retest now        | `findings:verify` and the server's `can_retest` (the Proof of fix section) |
  | In progress                        | Mark fix applied  | status permission, not a people-written finding, the lifecycle's move      |
  | Resolved, accepted, false positive | none              | (Add to task stays in More)                                                |
  | Any other state                    | Add to task       | task write permission and the remediation module                           |

  Mark fix applied asks the lifecycle for the move when clicked (as the status menu does) and then takes the
  status menu's path: the note dialog, the organization's move fields, approvals and Undo are unchanged.

- **Watchers** row: the summary ("2 watching") opens the manage sheet; your own Watch toggle is an icon button
  named by its action ("Watch this finding", "Stop watching this finding"), pressed while you watch.
- **Tabs**, right under the header, kept in the URL (`?tab=`): Overview (why it matters, the fix, the scanner
  output, proof of fix), Evidence, Validation (only when there is a result or a reachability check to run),
  Remediation, Data flow (`attack-path`, only with a data flow), Pentest details (findings people wrote),
  Related, Details (analysis, description, type sections, scores, identifiers, sources, discovery, import
  history).
- **Bands** (approval request, SLA overdue, remediation task) sit above the panel on every tab.
- **Properties** (`FindingProperties` on `PropertyList`): a rail beside the panel from 1280 px (19rem, sticky);
  below that it sits under the header, in two columns while there is room; on a phone it is a card of 44 px
  rows with "Asset, dates and more" folded, after the bands.
- **Activity** is the summary under the properties; it opens the activity panel (`?activity=open`).
- On a phone the header starts with the way back to the list ("< Findings", or the list's name) and the
  position; the main action leads the action row.

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

## Scanner-supplied text

Snippets, stack frames, data-flow steps and file paths come from scanner output and
are untrusted. `CodeHighlighter` and the path/message texts go through
`lib/untrusted-text.ts`: bidi and other control characters show as visible `\u{XXXX}`
escapes (a line cannot reorder what the reader sees), and a snippet over 20,000
characters is cut with "Show more" (the expanded view is capped at 70,000; Copy copies
the whole text). The Related tab shows only the groups that have data (similar,
linked, same CVE), or an empty state; the Remediation tab shows no progress header
because the finding record carries no tracked steps.

## Known gaps

- The type-specific fields are stored since #823 (columns) and #849 (the typed
  `type_details` document: a secret's 4+4 preview, fingerprint, scopes and
  rotation; a misconfiguration's policy name and cause). Findings stored before
  then show these sections from their next ingest. A secret value is never
  stored or returned: the preview has at most the first and last 4 characters.
- Upgrade commands cover the common ecosystems. An unknown ecosystem shows the
  version change without a command.
