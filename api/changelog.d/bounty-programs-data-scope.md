### Added: program members see and scan their programs

- The assets a bug-bounty program covers are assigned to the program group (`asset_owners`, source `program`), after every program change, after scan results land and every 30 minutes. Members of the group see those assets and their findings and nothing else of the organization; pausing or ending the program takes the access away. RFC-065.
- A restricted member may scan a typed target that an entry of one of their programs covers (program exclusions apply); other typed targets stay refused.
