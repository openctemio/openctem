### Security: one organization can no longer skip e-mail verification for the others

- Verifying an e-mail address is a property of the account. An organization set to `never` made sign-in skip verification for every organization the account belongs to. The setting `never` is retired (refused on save, a stored value reads as `auto`), and `always` now means "members must have a verified address to enter this organization": entering it is refused until the address is verified, while the account's other organizations are unaffected.
