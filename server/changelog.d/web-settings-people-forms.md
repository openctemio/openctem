### Fixed: settings show people as people, whole web-address names and filled-in text

- Settings > Members lists people only. Service accounts used to appear there as members with a synthetic `svc-…@service-accounts.invalid` address and no roles; they are listed under Settings > Service accounts, and the member figures above the list count people only. The member list API takes `account=person|service` (both when left out) and marks each service account with `service_account`; pickers that list both can mark them.
- Settings > General: "Name in the web address" takes a whole row and keeps room for the name; the site address in front of it gives way first and ends in an ellipsis. The organization sign-up form uses the same field.
- An import mapping's page says "Imports choose it as format <name>." instead of showing an unfilled `{format}`. A test now fails on any `t()` call that leaves a placeholder of its English or Vietnamese string unfilled.
- Docs: none (the pages behave as their help already describes; the API field is listed in the generated API reference)
