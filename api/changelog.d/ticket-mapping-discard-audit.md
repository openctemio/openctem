### Security: discarding a ticket mapping draft is audited

- `DELETE /api/v1/integrations/ticket-mappings/{mapping_id}/draft` now writes a `ticket_mapping.updated` audit row (actor, the discarded draft as "before", the published version as "after"), like saving the draft does. Discarding when there is no draft changes nothing and writes no row.
