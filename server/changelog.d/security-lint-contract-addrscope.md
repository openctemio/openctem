### Fixed: security lint compares the API SSRF tables with the contract module addrscope

- sdk-go moved its deny list from ctis addrscope to the contract module; rule 6 now reads the module path from sdk-go's own import and checks the API tables against that source (both directions), instead of falling back to a table diff that no longer exists.
- The API httpsec tables are unchanged.
