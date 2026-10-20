### Security: one outbound gate for tracker content; linking an issue needs findings:fix_apply

- Every path that sends content to Jira or GitHub Issues (create ticket, workflow `create_ticket`/`update_ticket`, task issues, campaign tickets, status pushes) asks one gate. Pentest findings leave only through their campaign's ticket action (campaign lead); the generic route, workflows and task issues answer 403 `TICKET_EGRESS_REFUSED`.
- TLP:RED campaign content is never sent. A campaign above the organization's tracker limit (new pentest setting `ticket_max_tlp`, default `amber`; `red` is refused) is refused, and status pushes for it stop.
- Secret findings no longer send the masked preview to trackers (location only). Findings with a data exposure risk above `none` send severity, status and location only, with the title "Data exposure finding".
- `POST /api/v1/findings/{id}/ticket-links` (link an existing issue) now also needs `findings:fix_apply`: Done on a linked issue is a fix claim.
- **Upgrade note:** roles with `findings:write` but without `findings:fix_apply` can no longer link existing issues; workflows that ticketed pentest findings now fail that step.
