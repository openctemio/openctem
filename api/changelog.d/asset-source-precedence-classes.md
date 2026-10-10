### Behaviour change: asset source precedence per attribute class

- Source precedence is now a ranked list per attribute class (identity,
  network, software, ownership, cloud tags, lifecycle) with a default list
  the classes inherit. A row names a kind or one source (`scan:nmap`), with
  its own TTL and a trust switch. New source kind `feed` for passive and
  published feeds.
- `GET/PUT /api/v1/organization/settings/asset-reconciliation` take
  `{"default": [...], "classes": {...}}`; `GET` also lists the sources that
  reported the organization's assets. `POST …/preview` shows what a policy
  would change before saving.
- Demoting a connector source needs step-up re-authentication. After a save
  the organization's assets are re-resolved in the background; changed
  values appear in the asset timeline.
- **Upgrade note:** settings saved in the previous shape (`precedence`,
  `ttl_days`) are ignored and the defaults apply; set them again under
  Settings > Asset sources. A migration (`asset_source_kind_feed`) widens the
  source kind check.
