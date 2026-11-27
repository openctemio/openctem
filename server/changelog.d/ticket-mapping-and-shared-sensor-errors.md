### Fixed: ticket mapping and shared sensor refusals say what is wrong

- `POST /integrations/ticket-mappings` answered 400 "Invalid request" for every refusal. A wrong field now answers 400 `TICKET_MAPPING_INVALID_FIELD` with `details.params.field` (`object_kind`, `project_key`, `issue_type_id`, `name`, `preset`, `integration_id`, ...) and a sentence saying why, for example "issue_type_id is not valid: it is required (the id of the issue type in the project ...)". An integration that is not a connected Jira site answers 409 `TICKET_MAPPING_TRACKER_NOT_CONNECTED`.
- `PUT /admin/settings/shared-sensors` turning shared sensors on before they are available now names what is missing: 409 `SHARED_SENSORS_NOT_READY` with `details.params.missing` ("shared job claiming, per-job isolation on shared sensors").
- Docs: server/docs/architecture/ticket-field-mapping.md, server/docs/architecture/sensors.md
