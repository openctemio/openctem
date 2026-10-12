### Fixed: the Scope page says "Add to scope" when a member's entry applies at once

- Members without the approve permission saw "Request access" on the Scope
  page, on the scope check's fix buttons and in the rule dialog's summary even
  when scan approval is Off or On, where their entry takes effect immediately.
  These now say "Add to scope" (or "Allow for N days" for a one-off); "Request
  access" appears only under Strict scan approval. Under Off and On the button
  also shows when the organization does not accept member requests, since
  nothing is requested.
