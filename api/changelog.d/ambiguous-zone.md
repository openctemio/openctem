### Behaviour change: overlapping scan zones of different sites no longer tie-break by name

- When two or more scan zones hold a target at the same narrowest range and their assigned sensors differ (two sites that reuse 10.0.0.0/16, an office and a cloud network), the target is no longer sent to whichever zone name sorts first. It is not scanned and is reported with kind and refusal code `ambiguous_zone` (fix `pick_zone`): pick the scan's zone (site) in the scan form, and it runs there. Zones that hold the same range with the same sensors still route as before (first by name), a narrower zone still wins over a wider one, and disjoint zones are unchanged.
- A scan whose saved target lies in such a tie is still accepted at create, since it is inside zones; the trigger and the scope check ask for the zone.
- Creating or updating a scan zone returns `same_range_zones`: the organization's other zones that hold one of its ranges exactly, so the console can warn that scans of those addresses will ask which site.
- Tenants that relied on the name tie-break see `ambiguous_zone` until they pick a zone for those scans, or give the zones the same sensors, or narrow one of the ranges.
