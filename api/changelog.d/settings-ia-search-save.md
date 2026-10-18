### Changed: settings are grouped by what they protect, and search finds individual settings

- The settings area has eight groups: My account, Organization, Security (Authentication, Domains, Trusted organizations, SSO approvals, Support access, Audit log), Access (Members, Teams, Roles, Directory sync, API keys, Service accounts, AI assistants), Findings & assets, Scanning, Scanner content and Integrations. Page URLs are unchanged.
- Search in the settings rail, on the Settings page and in the command palette finds the settings inside a page (for example "IP allowlist" or "interactsh"), opens the page at that setting and outlines it.
- The sensor scan-job controls (private targets, out-of-band callbacks, custom templates, tool User-Agent and TLS, sensor identity and key binding, shared sensors) moved from Authentication to the new Scanning › Sensor job safety page. They are still saved in the security settings and still change only for the owner.
- Settings forms on General, File storage, Authentication, Sensor job safety and Modules save through one sticky bar shown while there are unsaved changes, with Ctrl/⌘+S, and ask before you leave with unsaved changes.
- Authentication and Sensor job safety list the changes that weaken protection (for example two-factor no longer required, an emptied IP allowlist, callbacks allowed) and ask for confirmation before saving, and show who changed them last.
- General has one danger zone (transfer ownership, delete the organization); only the owner can edit the URL slug, as the API already required.

### Fixed: honest settings copy and states

- Authentication no longer mentions a session length setting, and General no longer mentions localization: neither exists.
- File storage shows an error when its settings cannot be read instead of showing "Local filesystem" as if it were saved, and reports the server's reason when a save fails.
- The pages are translated into Vietnamese.
