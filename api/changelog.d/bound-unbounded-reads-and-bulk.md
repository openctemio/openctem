### Security: unbounded reads and bulk inputs are now capped

- Four collection reads under one parent (attachments of an object, owners of an asset, role bindings of a team and role-to-team bindings, assets of a business service) return at most 1,000 rows in a stable order, so one runaway parent can no longer load an unbounded set into memory. The software list of an asset and the program list were already capped.
- `PATCH /api/v1/asset-groups/bulk` and `DELETE /api/v1/asset-groups/bulk` refuse more than 1,000 `group_ids` with a validation error.
- `POST /api/v1/credentials/import/csv` refuses a CSV of more than 10,000 records (header included) with 400 before any dedup work starts; the 10 MiB body limit bounded bytes only.
