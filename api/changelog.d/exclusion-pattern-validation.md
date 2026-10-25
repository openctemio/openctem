### Fixed: scope exclusions that can never match are refused

- An `ip_address`, `ip_range` or `cidr` exclusion must parse the way the scan dispatcher parses it (a reversed range or a /33 block is refused), and a `domain` or `subdomain` exclusion must be a name, not a URL. Before, such a typo was saved and silently excluded nothing.
