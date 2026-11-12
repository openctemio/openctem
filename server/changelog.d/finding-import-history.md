### Added: import history and KEV chip on the finding page

- The finding page's side rail lists every upload or run that acted on the finding, newest first, with what it did (new, still detected, reopened, resolved, suppressed by a rule, held for review), the tool and when. A run opens its run page. The list comes from the existing `GET /api/v1/findings/{id}/imports` read, which answers 404 outside the caller's data scope; the panel is then hidden. No API change.
- The page header shows the KEV chip (and Ransomware when CISA marks it) first, when CISA lists the finding's CVE.

### Fixed: "Last seen in" no longer calls a rule decision "still detected"

- A receipt that stored a new finding as decided by a suppression rule, or held it for review, was described as "still detected it" on the finding page. It now says what happened.
