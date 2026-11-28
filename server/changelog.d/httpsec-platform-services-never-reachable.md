### Security: outbound calls never reach the platform's own services

- A private range opened on the server or in the console (System > Private networks) applies to every organization's webhooks and integrations. The platform's own services inside such a range (database, cache, web, gateway, the admin console and the API itself) are now refused like loopback and cloud metadata: the server resolves their hosts at start-up and every minute, and no opened range unlocks them. More hosts can be listed in `OPENCTEM_HTTPSEC_PLATFORM_HOSTS` (compose sets the admin console). The private-destination check in the console names the reason ("one of the platform's own services").
- The platform AI "allow private" switch goes through the same guard: it still reaches an ordinary private address (a self-hosted model server), never a platform service, loopback or a metadata address.
- A single-host install that runs a self-hosted service on the API's own address can no longer reach it from outbound calls; move it to another address.
- Docs: server/docs/architecture/outbound-requests.md
