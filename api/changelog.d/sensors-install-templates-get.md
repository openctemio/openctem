### Fixed: the sensors page no longer writes when it loads
- `GET /api/v1/sensors/install-templates` returns the install commands without a pairing code (same permission as the POST). The Add sensor panel reads it with GET on load; the POST stays for commands that carry a pairing code, and is sent only after the user created a code.
