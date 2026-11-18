### Changed: the findings state "Dispositioned" is called "Dismissed"

- The state filter on the findings list, the vulnerability list state label and the findings lens descriptions now say "Dismissed" (Vietnamese "Không cần sửa") for false positives, accepted risks and duplicates that are closed without a fix and never counted as fixed. The Closed description reads "Fixed and dismissed together".
- Only the words shown to people change. The `state=dispositioned` URL parameter and API value are unchanged, so links and saved views keep working.
- Docs: web/docs/findings-list.md ("Practice and State chips")
