### Changed: the asset page follows the redesigned detail layout (redesign branch)

- Header: the asset type and its scope, exposure and criticality as chips above the name, and a More menu (Copy
  link, Copy ID, Open the list of this type). On a phone the way back to Assets leads the header, the chips wrap
  onto lines and More sits at the end of the name's line. The criticality chip in a header (page and drawer) shows
  its level by bars and word without a solid fill.
- Tabs sit right under the header: Overview (next steps, scan window), Relationships with
  its count (when the relationships module is on), How we found this (ownership and scope, lineage, where values
  come from, freshness, coverage, identifiers), Ports and services (domains and subdomains), Web (web origins, or
  any asset a sensor kept web evidence for), Owners and access, and Activity (the timeline; its "Why" opens How
  we found this). The active tab is in the URL (`?tab=`).
- Owners and access, and Relationships, were only in the asset drawer; the page now shows them with the same
  components, permissions and module switch, loaded when their tab opens.
- Properties (risk score, open findings, status and liveness, type, ID, description, tags) are a plain list
  beside the panel from 1280 px, under the header below that, and a card of rows on a phone with the ID,
  description and tags folded.
- A tab's reads start when the tab opens; the page loads the related-assets count with the asset. No permission
  or API change. A repository still opens its workspace.

Docs: web/docs/asset-detail.md
