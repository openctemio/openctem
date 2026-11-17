### Changed: the finding page follows the redesigned detail layout (redesign branch)

- Header: type and identifier chips, the place in the list with previous and next ("2 of 27" links back to the
  list), the title, one main action chosen by the finding's state (Open the original for a duplicate, Retest now
  once a fix is applied, Mark fix applied while in progress, Add to task otherwise; each with the permission it
  has elsewhere on the page), Re-verify and AI triage beside it, and a More menu (Copy link, Copy finding ID,
  Create ticket, Mark as duplicate). On a phone the way back to the list leads the header.
- Tabs sit right under the header: Overview (why it matters, the fix, scanner output, proof of fix), Evidence,
  Validation (results and the reachability check, when there is one), Remediation, Data flow, Pentest details,
  Related and Details (description, scores, identifiers, sources, discovery, import history). Existing `?tab=`
  links keep working. The Evidence count no longer includes validation results, which have their own count.
- Properties are a plain list beside the panel from 1280 px, under the header in two columns below that, and a
  card of 44 px rows on a phone with "Asset, dates and more" folded. Approval, overdue and task bands sit above
  the panel on every tab.
- The watchers row keeps to one line: the Watch toggle is an icon button named by its action and pressed while
  you watch; both controls use the standard sizes (32 px, 36 px on a phone).
- No permission, status move or API change.

Docs: web/docs/finding-detail.md
