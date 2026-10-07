### Changed: the asset Ownership card says what each choice does, and whether scans may reach the asset (web)

- The card is now "Ownership and scope". It answers two questions side by
  side: is the asset ours (state, confidence, evidence), and may scans reach
  it (the scope entry, seed or verified domain that covers it, or "Out of
  scope" with an "Add to scope" action).
- The decision buttons have plain labels ("Ours", "Not ours", "Ours, on
  third-party infrastructure", "Watch only", "Undo the decision") and the
  consequence of each is written next to it, not only in a tooltip.
- The card states that confirming ownership does not authorize scanning
  (RFC-054 §4.2): a scope entry decides what scans may reach.
