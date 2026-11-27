### Security: the gateway and all-in-one images carry Caddy 2.11.9 and patched dependencies

- The gateway (`openctem-gateway`) and the all-in-one image now build Caddy 2.11.9 (was 2.11.4) and, in the gateway, caddy-l4 0.1.3. This fixes the hop-by-hop header handling advisory GO-2026-6874 in Caddy itself.
- The Caddy build also raises `golang.org/x/net` to 0.62.0, `github.com/klauspost/compress` to 1.20.2 and the OpenTelemetry modules to 1.47.0. That fixes the advisories the release image scan and govulncheck reported against the Caddy binary: CVE-2026-116587 (go-jose, through the newer Caddy release), CVE-2026-63209 and GO-2026-6865 (compress), CVE-2026-78661 (x/net), and GO-2026-6975, GO-2026-6974, GO-2026-6615, GO-2026-6508 and GO-2026-6505 (OpenTelemetry).
- The Caddyfile is unchanged and adapts the same with the new release.
- Docs: none (image build only, no configuration or behaviour change)
