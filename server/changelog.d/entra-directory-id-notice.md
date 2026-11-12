### Changed: the admin console flags an Entra ID provider that has no directory ID

- A saved Entra ID provider whose Directory (Tenant) ID is a domain name, `common`, `organizations`, `consumers` or empty is marked "Needs directory ID" with a notice that members see "SSO not configured" until the directory GUID is entered, so the administrator can correct it.
