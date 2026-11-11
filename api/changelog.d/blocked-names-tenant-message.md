### Changed: a refused government name tells the organization who can help

- Adding a government or military domain to scope now says "Government and military domains are blocked on this installation. Your platform administrator can grant an exception." (code `GOVERNMENT_NAME`, in the scope dialog, bulk add and rule suggestions), and the scan-time refusal "Not allowed by the platform" says the same for such names. No other organization's exceptions are ever shown.
- New operator guide: Blocked target names and exceptions (`api/docs/how-to/blocked-target-names.md`), including the operator's responsibility to verify the written authorisation.
