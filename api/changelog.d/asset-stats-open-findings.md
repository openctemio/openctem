### Fixed: asset stats count open findings only

- `GET /api/v1/assets/stats` returned `with_findings` and `findings_total` over every finding status, so resolved, false-positive and accepted findings raised "assets with findings" and the findings total above what the asset list, its "Has open findings" filter and each row's count show. Both now count the open set (new, confirmed, in progress, fix applied), branch-only findings left out, like the rest of the inventory.
