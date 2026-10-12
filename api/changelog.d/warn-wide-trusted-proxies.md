### Security: wide trusted-proxy ranges are reported at startup

- A trusted proxy may set the client address the API believes (login rate limits, audit addresses, IP allowlists). Trusting a whole container network trusts every container on it, including a sensor running third-party tools.
- The API now logs a `SECURITY:` warning at startup, and `server -check-config` prints a warning, for each `SERVER_TRUSTED_PROXIES` or `SENSOR_MTLS_TRUSTED_PROXIES` range wider than 16 addresses (an IPv4 `/28`, an IPv6 `/124`). Nothing is refused.
- **Upgrade note:** replace a network range such as `172.18.0.0/16` with the gateway's and the web server's own addresses (give those containers fixed addresses, as the shipped Compose file does).
