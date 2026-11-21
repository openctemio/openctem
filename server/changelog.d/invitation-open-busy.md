### Fixed: the invitation page says why Open failed and when to retry

- When opening an accepted invitation's organization is refused for now (too many token requests from one address, a server failure, or no answer), the invitation page shows the reason and a "Try again in N s" wait taken from the server's `Retry-After`, then offers Open again. It no longer shows the same Open button with no reason.
- Added `RATE_LIMIT_TOKEN_EXCHANGE_PER_MIN` (default 20, per address). Only a test stack where every simulated browser shares one address raises it; production refuses a value above 20.
- Docs: server/docs/configuration/environment-variables.md
