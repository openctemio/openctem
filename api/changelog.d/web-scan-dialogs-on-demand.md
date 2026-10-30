### Changed: Scans pages load the scan wizard when it opens

- The new, quick, edit and clone scan dialogs, the scan-assets dialog and the
  run drawer load the first time they open instead of with the page. Scans
  pages, the external attack surface and asset detail no longer download the
  scan wizard (workflow graph, form schemas, schedule parsing) up front.
