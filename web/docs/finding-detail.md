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
metadata, activity) is one tab or one disclosure away.

## What the best tools do

Studied October 2026 from public docs:

- **GitHub Dependabot alert.** The fix comes first ("Create Dependabot security
  update" at the top), along with the patched version and EPSS. Assignees and tags
  sit in a right panel. A dismissal needs a reason, which goes into the timeline.
  ([viewing alerts](https://docs.github.com/en/code-security/dependabot/dependabot-alerts/viewing-and-updating-dependabot-alerts),
  [advisory data](https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database))
- **GitHub code scanning.** Metadata is on the right and the code on the left. "Show
  paths" lists the source-to-sink steps. Rule help folds behind "Show more", and
  autofix is offered inline.
  ([about alerts](https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/about-code-scanning-alerts))
- **GitHub secret scanning.** Validity is Active / Inactive / Unknown, with a
  re-verify button and the token's metadata.
  ([evaluating alerts](https://docs.github.com/en/code-security/secret-scanning/managing-alerts-from-secret-scanning/evaluating-alerts))
- **Snyk issue card.** Shows the priority score and the factors behind it (exploit
  maturity, reachable, trending), "Fixed in", and an **"Upgrade to x.y.z"** button,
  with the rest of the actions under "⋯". The factors only appear on hover, which is
  weak.
  ([issue card](https://docs.snyk.io/scan-fix-and-prevent/scan-with-snyk/snyk-projects/issue-card-information.md))
- **GitLab vulnerability page.** Status and severity are in a sidebar. The body is a
  set of collapsible sections in a fixed order: Risk (CVSS, EPSS, KEV), Remediation,
  Details, Evidence, Related, Activity.
  ([docs](https://docs.gitlab.com/user/application_security/vulnerabilities/))
- **Tenable VM.** The finding pane is different for each finding type. The VPR key
  drivers are global threat data and are labelled as such.
  ([finding details](https://docs.tenable.com/vulnerability-management/Content/Explore/Findings/ViewFindingsDetails.htm),
  [risk metrics](https://docs.tenable.com/vulnerability-management/Content/Explore/Findings/RiskMetrics.htm))
- **Jira and Linear.** The narrative is in the main column and the properties are in
  a right rail. Jira hides empty fields. Comments are a feed under the issue
  ([Jira field layout](https://support.atlassian.com/jira-software-cloud/docs/configure-field-layout-in-the-issue-view/),
  [Linear comments](https://linear.app/docs/comment-on-issues)).
- **Wiz.** Treats toxic combinations and attack paths as the reason an issue
  matters. This comes from its public material; the issue page itself is behind a
  login.

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
5. **Activity is a tab, not a permanent column.** The old layout gave a third of the
   width to a feed with one entry.
6. **The page and the drawer share their parts,** so they cannot disagree:
   `toFindingDetail`, `useFindingTriage` (including the approval rule),
   `FindingWhyItMatters`, `FindingFixCard` and `FindingProperties`.
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
│ Also fixed in 6.0.6 (other release lines)     │
└──────────────────────────────────────────────┘
Overview | Evidence | Remediation | Attack path | Activity (n) | Related
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

- The API does not persist the type-specific fields: `finding_type`, `secret_*`,
  `misconfig_*`, `compliance_*` and `web3_*` are never written or read by the
  finding repository. The entity and the API response carry them, but they arrive
  empty after a reload. Until that is fixed, the secret, misconfiguration,
  compliance and web3 sections stay hidden. The secret Fix card still shows,
  because it keys off `source = secret`.
- Upgrade commands cover the common ecosystems. An unknown ecosystem shows the
  version change without a command.
