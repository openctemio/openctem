### Added: an opt-in HTTPS proxy for the platform's own feeds

- `OPENCTEM_HTTPSEC_FEED_PROXY` (`http://[user:password@]host:port` or `https://...`) routes the vulnerability bundles, CISA KEV, EPSS, the CTEM-ID catalog, the public program feed and the release feed through a corporate proxy; `OPENCTEM_HTTPSEC_FEED_NO_PROXY` lists hosts reached directly (an internal mirror). Webhooks, integrations, identity providers and anything an organization configures never use it, and `HTTPS_PROXY` is still not read.
- The destination is checked before the request reaches the proxy (blocked literals, dangerous names, blocked local answers); only https destinations are proxied, with TLS end to end, and the API refuses to start on a malformed value without echoing the password.
- A vulnerability bundle URL whose name does not resolve at start-up no longer disables the import until the next restart: each fetch is checked when it is made.
- The air-gapped guide lists the outbound hosts to allow and how KEV and EPSS arrive offline with the signed bundles.
