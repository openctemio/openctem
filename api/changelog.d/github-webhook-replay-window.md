### Security: a captured GitHub webhook delivery cannot be replayed

- The inbound GitHub webhook remembers each verified `X-GitHub-Delivery` id per organization for 24 hours (in Redis, shared by every API replica). A replay of the same signed delivery is acknowledged and ignored, so it can no longer re-close or re-open a linked finding.
- A delivery without a valid `X-GitHub-Delivery` header is refused (400); if Redis is unavailable the webhook fails closed (503).
- The public route has a per-IP budget in front of the per-request secret lookup.
- Note: GitHub's "Redeliver" button reuses the delivery id, so a redelivery inside 24 hours is ignored as well.
