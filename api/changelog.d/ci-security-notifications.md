### Security: administrators are told about every CI break-glass and about bursts of refused CI tokens

- Creating a CI break-glass, and each run it lets pass, now notifies every active owner and administrator in-app and sends the new `ci.break_glass` notification event (on by default).
- The CI alert job raises `ci.token_refusals` (on by default, once while it lasts) when a tenant has at least 20 refused CI token exchanges in 30 minutes; it now also walks tenants that have a trust configuration but no pipeline yet.
- Migration `001111`: two event-type catalog rows and the `token_refusals` alert-state kind.
