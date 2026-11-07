### Security: golang.org/x/net 0.62.0

- The API and the signer are built with golang.org/x/net 0.62.0, which fixes CVE-2026-78661 (denial of service from crafted HTML input) and CVE-2026-97045 (cross-site scripting through namespace handling when rendering HTML) in its HTML package. No configuration change.
