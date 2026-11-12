### Added: short search syntax for filters

- The query language takes a second spelling for search boxes: `severity>=high kev=true -status:accepted last_seen<7d domain=*.example.com`. `field=value` and `field:value` are both accepted (`:` takes comma lists), `=` is exact, `*` and `?` are patterns on name fields, `~` is contains (3 characters or more), `-` negates, `>`/`>=`/`<`/`<=` compare numbers, times and ordered values (severity, priority, asset criticality), `lo..hi` is a range, `AND`/`OR`/parentheses group, and plain words stay a text search. A bare IP address, CIDR range or CVE id becomes a condition on the asset address or the CVE.
- Ages: `last_seen<7d` is "seen in the last 7 days"; the signed form `last_seen<-7d` is still a point in time. Minutes (`30m`) are accepted in both forms.
- Short names (`cve`, `kev`, `epss`, `port`, `domain`, `ip`, `last_seen`, `age`, ...) resolve to their fields; the canonical text always prints the field path.
- Query problems now carry a `code` (`unknown_field`, `operator_not_allowed`, `unknown_value`, `bad_value`, `pattern_not_allowed`, `syntax`, ...) and `suggestions` ("did you mean", from the fields the caller may use only). Messages never repeat a value from the query.

### Changed: query language details

- `severity > high` and other range comparisons on ordered values are now valid (they mean the values above high) instead of an error.
- A `~` (contains) search needs at least 3 characters.
