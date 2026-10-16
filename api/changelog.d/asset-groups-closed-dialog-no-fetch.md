### Fixed: a closed dialog no longer loads the whole asset group list

- A disabled asset group list (the closed Edit scan dialog, a group scope rule
  dialog on another rule type) sent `GET /asset-groups` anyway, so the Scans
  page and every page holding such a dialog paid one extra request on load.
  It now sends nothing until the dialog needs the list.
