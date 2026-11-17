# Asset page

How `/assets/[id]` is laid out, and why. The code is in
`src/app/(dashboard)/(discovery)/assets/[id]/page.tsx`; the layout rules are "Detail pages" in
`ui-style-contract.md`, and `/findings/[id]` (`finding-detail.md`) is the reference page.

## Layout

- **Header** (`DetailPageHeader`): the asset type, scope, exposure and criticality as chips, the name as the
  page's only `h1`, and the More menu: Copy link, Copy ID, Open the list of this type. Status is a property, not
  a header chip. The criticality chip shows its level with the bars and the word on the plain pill (no solid
  fill: next to the actions it would read as a button). Below 768 px the first line is "‹ Assets", the chips wrap
  onto lines, and More sits at the end of the name's line.
- **Tabs** right under the header, the active one in `?tab=`:

  | Tab                | Key             | Shown when                               | Content                                                                                |
  | ------------------ | --------------- | ---------------------------------------- | -------------------------------------------------------------------------------------- |
  | Overview           | `overview`      | always                                   | next steps, the scan window (hidden when none)                                         |
  | Relationships n    | `relationships` | the relationships module is on           | `AssetRelationshipsTab` (add, edit, delete, open a related asset)                      |
  | How we found this  | `found`         | always                                   | ownership and scope, lineage, where values come from, freshness, coverage, identifiers |
  | Ports and services | `ports`         | domain, subdomain                        | open ports of the addresses it resolves to                                             |
  | Web                | `web`           | web origin types, or web evidence exists | web evidence, the origin's own section                                                 |
  | Owners and access  | `owners`        | always                                   | `AssetOwnersTab` (owners, groups, access grants)                                       |
  | Activity           | `activity`      | always                                   | `AssetTimeline`; "Why" opens How we found this                                         |

- **Properties** (`PropertyList`): risk score (the value with its mark; the label names it), open findings (a link to the asset's findings), status and
  liveness, type; then ID, description and tags (folded on a phone). Beside the panel from 1280 px, under the
  header below that.
- A repository keeps its own workspace at the same URL.

## Loading and requests

- The asset is read through the page view (`GET /assets/{id}/view` primes the panels' reads), then
  `GET /assets/{id}`.
- Two reads decide the tab strip and load with the page: the related-assets groups (the Relationships count,
  the same request the tab makes) and the web evidence (whether the Web tab shows). The page waits for them
  (`SettleGroup`, at most 1.5 s), so the strip does not change after it painted.
- Every other panel reads its data when its tab opens. Owners and access and Relationships also load their
  code then (`next/dynamic`), so the page's first-load JavaScript stays where it was.

## Not on the page yet

Items of the design with no data source today, left out rather than drawn empty: an attack-path count through
the asset, the risk score breakdown, top findings, a technologies tab, a one-line summary under the name, and an
environment property. The design's figure tiles are not used: risk score is a fact (a property), and open
findings links to its list from the properties.
