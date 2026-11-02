# CTEM-ID mapping

Our exposure taxonomy (`exposure.EventType`, [exposure taxonomy](exposure-taxonomy.md)) is the primary
one. For interoperability, an exposure also carries the matching **CTEM-ID** code, such as `CTEM-DOM-2`,
when the data we hold settles one. CTEM-ID is the exposure identifier scheme published at
https://ctem.org.

Status: **shipped**. Catalog version followed: **1.0** (29 codes). Codes derivable today: 9.

Key files:

- `pkg/domain/ctemid/ctemid.go`: the codes, `CatalogVersion`, `Code.URL()`.
- `pkg/domain/ctemid/mapping.go`: `Map`, the rules and the "no code" cases.
- `internal/app/exposure/enrichment.go`: picks the code with the linked asset in view.
- `internal/infra/http/handler/exposure_handler.go`: `ctem_id` on the exposure response.
- `web/src/features/exposures/components/exposure-enrichment.tsx`: the CTEM-ID row on the exposure detail.
- Migration `20261102020530_drop_ctem_id_catalog`: drops the old downloaded catalog table.

## Why a mapping, and why derived

A CTEM-ID names an exposure class together with who owns or relates to the exposed thing (the
organization, a vendor, an employee, a customer, an unrelated party) and sometimes how it was found. An
event type names the class only. So the code is a function of the event type, its details and the linked
asset, and "no code" is a valid answer: the mapping never guesses.

The code is computed on every read from a static table in code, like the display category and summary.
Nothing is stored, so a rule change applies to every exposure at once, with no migration. The rules follow
one catalog version (`CatalogVersion`), which a change of codes or rules bumps.

There is no per-exposure manual tag. To change an exposure's code, correct the input it is chosen from
(the asset's scope or type, the leaked credential's classification) and the code follows.

## Rules

| Code | Event types | Chosen when (basis) |
|---|---|---|
| `CTEM-DOM-1` | `lookalike_domain` | `details.technique` is one of omission, repetition, transposition, replacement, insertion, hyphenation, bitflip, tld (`lookalike_technique`) |
| `CTEM-DOM-2` | `lookalike_domain` | `details.technique` is homoglyph (`lookalike_technique`) |
| `CTEM-CRD-1` | `credential_leaked` | `details.source_type` is a public dump (data_breach, dark_web, paste_site, underground_forum) and `details.classification` is internal (`credential_dump`) |
| `CTEM-CRD-2` | `credential_leaked` | same sources, classification vendor (`credential_dump`) |
| `CTEM-EXP-6` | port_open, service_detected, web_interface_exposed, api_exposed, mcp_server_exposed | the linked asset is internet-facing and its scope is vendor (`asset_scope`) |
| `CTEM-EXP-5` | same | internet-facing, scope shadow (`asset_scope`) |
| `CTEM-EXP-3` | same | internet-facing, asset type firewall, scope not vendor, shadow or partner (`asset_type`) |
| `CTEM-EXP-4` | same | internet-facing, scope cloud, not a firewall (`asset_scope`) |
| `CTEM-SRC-3` | `repo_public` | the linked asset's scope is vendor (`asset_scope`) |

Internet-facing means the asset is marked internet accessible or its exposure is public. Every other
event type, and every case the table does not cover, has no code.

## Codes not derivable today

| Codes | Missing signal |
|---|---|
| BND-1 | no counterfeit-product source |
| DOM-3 | evidence of phishing use (content, kit, blocklist hit); MX, A or a certificate only show readiness |
| DOM-4 | a brand-plus-keyword lookalike generator; ours make character edits |
| EXP-1 | network placement: asset scope `internal` is the default for every asset, so it says nothing |
| EXP-2 | subsidiary or remote-site ownership on assets |
| FIN-1, FIN-2 | a financial data class on sensitive-data exposures |
| INF-1 to INF-7 | whose device a malware (stealer) log came from and how it used the identity; `source_type` malware only says a device was infected |
| RAN-1, RAN-2 | a ransomware leak-site source and the supplier or customer relation of the victim |
| SRC-1, SRC-2 | whether a public repository of the organization is sanctioned or an employee's own |
| SRC-4, SRC-5 | a source for unrelated third-party repositories, issues and comments |
| partner scope | affiliate and contractor read as different codes (EXP-2, EXP-6), so a partner asset gets none |

A new signal (for example device ownership on stealer records) is a new rule and a test in
`pkg/domain/ctemid`.

## API and console

`GET /api/v1/exposures`, `GET /api/v1/exposures/{id}` and the EASM exposure items carry:

```json
"ctem_id": {
  "code": "CTEM-DOM-2",
  "catalog_version": "1.0",
  "basis": "lookalike_technique",
  "url": "https://ctem.org/docs/ctem-dom-2"
}
```

The field is absent when there is no code. The exposure detail's "Security context" card shows the code
as a link to its ctem.org page, with our own short description in a tooltip (i18n, English and
Vietnamese).

## Security

- No outbound request: the platform no longer downloads the catalog (the `ctem-id-refresh` job,
  `CTEM_ID_FEED_URL` and `GET /api/v1/ctem-ids` are removed).
- No write path: the free-text `PUT /api/v1/exposures/{id}/ctem-id` tag is removed.
- The code is computed after the exposure passed the tenant and data-scope checks, from the asset the
  enricher loads under the caller's tenant. An asset that does not load contributes nothing.
- Details come from producers: the rules only compare them with fixed values; nothing from them reaches the
  code or the link.

## Licence

We hold the codes and our own descriptions only, never the catalog's titles or descriptions. CTEM-ID:
https://ctem.org, (c) SecureCoders and contributors, licensed CC BY-NC-SA 4.0.
