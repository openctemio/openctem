### Fixed: an accepted risk always ends, and the CI gate stops honoring it at that end

- A request to accept a finding's risk gets an expiry of 90 days when it names none, and is refused with an expiry in the past or more than a year ahead. A false-positive request no longer takes an expiry.
- Approving the acceptance writes the end to `findings.acceptance_expires_at`, which the CI gate reads; a finding accepted by an accepted-risk suppression rule takes the rule's expiry. The column is cleared whenever the finding leaves `accepted`.
- The web request dialog asks for the acceptance end (90 days ahead by default, at most a year).
- Migration `002117` adds the clearing trigger and fills the end for findings already accepted through an approval or a suppression rule.
