### Fixed: Scan assets and Quick scan do not start a scan with nothing to scan

- When the live scope check says none of the selected targets can be scanned, Start Scan is disabled and the dialog says why in place. A name that does not resolve in DNS reads "Nothing to scan: go.example.com does not resolve in DNS." with what to do and a "Check DNS again" button that re-runs the platform's resolution; other reasons are listed with their fixes. When only some targets can be scanned, the dialog says the scan runs on those and leaves out the rest.
- The selection summary shows its counts as separate elements instead of joining them with a middle dot, and says "1 does not resolve in DNS" in the singular.
- The refusal panel heading is translated (it was English only).
