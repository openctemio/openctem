### Added: console Content page for the content catalog

- Settings > Content catalog (`/settings/content`, `content:read`) lists the imported signed packages with type,
  search and installed filters, and opens a package to show its versions, permissions, license, dependencies,
  revocation, signatures and provenance.
- Members with `content:install` install, update (with what the new version asks for beyond the installed one
  highlighted), roll back, pin and uninstall packages, and approve, reject or cancel requests; the approval
  option (`settings:write`) shows a pending switch-off and its time.
- A banner warns when the signed index has expired or the revocation list is stale.
