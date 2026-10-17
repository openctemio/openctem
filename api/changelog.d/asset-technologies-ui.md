### Added: Technologies on the asset page; clearer Software tab

- The asset Overview has a Technologies section: chips grouped by category (web servers, frameworks
  and CMS, languages, JavaScript libraries, CDN, hosting, WAF and security, analytics, security
  headers), with the version when known and, on hover or focus, the tool's confidence, the source and
  when it was last seen. A Technologies tab lists every one with first and last seen (RFC-112).
- The Software tab shows only software components. A product without a CPE match reads "No CPE
  match: CVEs not checked" with an explanation instead of "Unrecognised"; the empty state explains
  where software comes from (CI SBOM uploads, service and version detection scans, an endpoint
  sensor) with links; a repository or application shows its component count and links to its
  components. The tab is translated (English and Vietnamese).
- Drawer tabs that do not fit the width move under a "More" menu instead of being cut off; the
  active tab always stays visible. This applies to every detail drawer.
- The asset header no longer shows "Zone: Internal", the zone every asset starts in, next to
  "Exposure: Public"; a zone someone set is still shown.
