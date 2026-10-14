### Changed: sensor Tool settings as a collapsible, searchable list

- The sensor drawer's Tool settings tab shows each tool as a collapsed row
  with its version and a summary ("All defaults", or "3 changed: rate-limit
  300, timeout 20, …"); tools with changes come first, then by name.
- A search box filters by tool or option name and opens the matching tool at
  the matching option. The open tools are remembered per sensor in this
  browser.
- Inside a tool the common options are open and the other groups are
  collapsed with their changed count; impact options keep their badge and get
  a short warning.
- Each changed option has a marker and "Reset to default"; "Reset tool" clears
  every option. One save bar per open tool appears only with unsaved changes
  (sticky at the bottom on a phone). Saving every option back to its default
  removes the stored settings. The save endpoints and permission checks are
  unchanged.
