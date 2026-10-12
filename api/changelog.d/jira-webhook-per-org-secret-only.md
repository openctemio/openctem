### Security: inbound Jira webhooks verify with the organization's own secret only

- The platform-wide `JIRA_WEBHOOK_SECRET` fallback is removed. It verified a delivery addressed to any organization (`?tenant=`), so whoever held it could forge Jira events, such as closing findings, for every organization.
- A delivery is accepted only when it is signed with a webhook secret of the organization it names. An organization without a secret has its deliveries refused (401).
- Startup now only warns about connected Jira integrations without a secret; it no longer refuses to start in production for them, because one organization's configuration must not stop the platform for the others.
- **Upgrade note:** startup refuses to run while `JIRA_WEBHOOK_SECRET` is set (even empty). Unset it, and have each organization with a Jira integration rotate its own secret (`POST /api/v1/integrations/jira/webhook-secret/rotate`) and put it in its Jira webhook.
