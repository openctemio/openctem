### Changed: Attack surface Suggestions tab with a Decide panel

- The Attack surface Review tab is now Suggestions. Each scope decision that
  still needs a person is one card: addresses behind your in-scope names,
  confirmed assets no scope entry covers, and the suggested rules for names
  found outside your scope. The tab and sidebar badge count cards, not rows.
  The overview shows the same cards; "Not now" hides a card there for a week.
- The row list stays one click away under "Show all items". A host row shows
  the services, certificates and web endpoints that follow it. The confirm
  action reads "Ours: add to scope", and the toast names the scope entries it
  added, with Undo.
- An address in a published CDN edge range is shown as shared space in the
  review rows too, and no scope fix is offered for it.
- Every string in the review queue, the overview card, the review reasons, the
  rule dialog and the asset Ownership card now comes from the en and vi
  dictionaries. The Scope settings page has a switch for
  `confirm_adds_to_scope`.
