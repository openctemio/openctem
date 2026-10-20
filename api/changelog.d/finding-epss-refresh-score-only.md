### Changed: the daily EPSS refresh rewrites a finding only when its score moved

- The refresh of open findings from the EPSS catalog compared and copied the percentile too, which changes for nearly every CVE on every feed, so almost every open finding with a CVE was rewritten each day. It now compares and writes the score only.
- A finding's `epss_percentile` is the rank in force when its score last moved or when it was scored; the current rank of a CVE is the one in the threat intelligence catalog.
