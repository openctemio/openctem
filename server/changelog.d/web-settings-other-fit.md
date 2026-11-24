### Fixed: settings and smaller pages fit every screen

- Tables that cut a column header on a tablet or a laptop with the sidebar open (audit log, scanning tools, capabilities, tool source keys, finding templates, credential leaks, a scan's runs, scan workflows) now fold their least important columns by the width they have, and the row menu stays in view.
- Long text no longer runs past its frame: a channel name in the notification history picker, the MCP connection commands (they wrap), template references, category labels, a workflow's readiness badge, the "Add executive summary" link and the leak date with its "Recent" mark.
- The ATT&CK coverage matrix wraps its tactic columns instead of scrolling sideways; the finding form's section chips are a swipe row with an edge fade.
- Explanations that stood as a row of their own above a list now follow it: report templates, priority rules, cycles (policy and operating rhythm), sensor products, import totals, exploration status (Refresh now moved to the toolbar), and the executive top risks hint (now the table's caption).
- One main action per screen: directory sync (SCIM), CI/CD and vulnerability scanners no longer repeat their header action in the empty state.
- A phone keeps the search box its room: Export (audit log), Refresh now (remediation suggestions), Import .nessus and Reset to defaults (modules, now in the list toolbar) are icons there.
- Vietnamese: notifications with a fixed server title (API key expires soon, and others) read in Vietnamese; dashboard names and notification bodies are marked as stored text; shorter labels for "View support activity" and "Try the rules on existing scans".
- Scope settings: a value in words goes under its label on a phone instead of squeezing it; scan profiles have a phone card where the name wraps and the marks and rule read whole.
- Pentest finding form: from 1280 px the action buttons sit over the summary rail (on two lines), never at the edge of a form field; below that a rule separates Save draft from Submit for review and Publish.

Docs: none (layout and wording only, no behaviour change)
