### Changed: continuous coverage starts a batch when it fills a task

- Coverage started a run as soon as one pair of a capability was due. Due times are spread over a tenth of the cadence, so pairs checked together came due again across many hours and each hour became its own run of a few targets (on one installation, 26 coverage runs a day, most carrying 3 to 5 targets).
- A capability's due batch now starts when it fills one task of its tool, or when its oldest due pair has waited a tenth of the cadence, at most 6 hours. Until then the pairs stay due and the batch collects the pairs that fall due meanwhile. Scans started by a person are not affected.
