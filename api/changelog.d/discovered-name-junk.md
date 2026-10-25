### Fixed: junk names from passive sources no longer become assets

- Domain and subdomain names are percent-decoded and lose what cannot start or end a host name (a leading "/" or quote from the URL they were cut from) when normalised: `%2Fwww.example.com` becomes `www.example.com`.
- At ingest, a domain or subdomain that is still not a host name after IDNA is not created, and a name that is the remnant of a percent-encoded delimiter (`2fwww.example.com`) is not created when the name behind it is in the same report or already in the organization's inventory. Each is reported in the ingest errors by its report id.
