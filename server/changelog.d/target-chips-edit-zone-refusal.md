### Fixed: A private range with no scan zone is refused as zone_none, and typed targets can be edited
- A private address or range that no scan zone covers is now refused with `zone_none` and the `add_zone` fix instead of `invalid_target`. Loopback, link-local and metadata addresses stay invalid.
- New scan, Targets step: a typed target chip can be edited in place (click, Enter or F2; Enter or blur commits, Escape cancels, an empty edit removes it).
- New scan, Targets step: the zone refusal group explains what to do, offers "Add scan zone" with the range prefilled when you may write scan zones, and a refusal code the form does not know shows the server's own reason.
