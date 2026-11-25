### Changed: one tab level on Attack surface and Assets

- Attack surface: the second row of tabs under the section tabs is gone. Technologies, Certificates, Web surface, Exposures, Lookalikes, Changes, Page changes, Discovery and Review are tabs of the one row (on a phone it swipes, with a fade at the edge). Posture is no longer a tab: the Overview's posture section links to it ("View posture details"), and the command palette still opens it. Every address keeps working.
- Attack surface Overview: the figures come first, then the posture. "What to fix to raise the grade" no longer shows as an empty heading: it lists the first fixes of the plan when there is something to fix, and is left out at the top grade.
- Assets, External surface view: the asset type (Domains, Subdomains, IP addresses...) is a "Type" filter token at the start of the list toolbar instead of a row of tabs under the Assets tabs.

Docs: web/docs/page-catalog.md, server/docs/architecture/list-query-contract.md
