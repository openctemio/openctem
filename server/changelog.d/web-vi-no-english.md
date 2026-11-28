### Fixed: Vietnamese pages no longer show English or code for rule conditions, connection errors, run reasons and capabilities

- Priority rules read their conditions as plain sentences in the reader's language ("Listed in KEV", "EPSS score is at least 50%", "Asset exposure is Private") instead of `is_in_kev = true`; the editor names its operators in words and now supports the asset exposure field the API already evaluates. One shared formatter serves the list, the editor and the dry run.
- Connection lists (integrations overview, notifications, SIEM, source control) word a failed connection from its code in the reader's language and show when a member turned one off as a local date, never "Disabled by user at 2026-11-27T08:59:36Z".
- Scan run reasons (scan detail, runs list, run sheet, last-run hover) word a known refusal code from the catalog; the server's English sentence is shown only to an English reader or when there is no known code.
- Capability names come from one catalog everywhere (discovery stages, workflow nodes, capability badges, server messages), with the missing capabilities added; attacker profile capabilities read "Network: …", "Credentials: …", "Keeps access".
- The platform console says "chưa tới một ngày" instead of "0 ngày" for an access request waiting less than a day.
- The support access banner keeps its case reference on one line, and on a phone the announcement and support banners take less height (the manage link follows the sentence).
- Docs: none (wording and layout of existing pages, no new behaviour)
