### Fixed: platform console text reads in Vietnamese

- Console: sign-in failures, "Could not create ..." errors, the content pack form checks, the target mapping form checks, the audit chain rebaseline reasons, the "New people" label of a verified domain and the "Failed to load" subjects of the account and content pack pages were English on a Vietnamese console; they now come from the catalog.
- Console: a "Too many attempts" answer on the identity provider, password change and approval pages follows the console's language.
- The console text test no longer exempts any file, and now also checks `setError`, `adminErrorMessage` and reason assignments.

Docs: none (wording only, no behaviour change)
