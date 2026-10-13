### Behaviour change: connector assets are in scope by default

- After a successful Tenable.sc connector sync, the public names and
  addresses it synced get their exact scope entries (origin `connector`), so
  scans may reach them. A new per-connector switch, `assets_in_scope`
  (default on), turns this off. Entries already added stay and are listed on
  the Scope page.
- Each connector's first successful sync only notifies the administrators
  that its assets will be added from the next sync. Later syncs add them,
  with an audit event per entry and one notice per sync.
- Never added: wildcards or ranges, private names, services, certificates or
  hosts, names already in scope, or anything while scan approval is Strict.
- Upgrade note: migration `scope_origin_connector` widens the origin check on
  `scope_targets`. It is safe on populated tables.
