### Fixed: a sensor report the CTIS validator refuses names each problem

- `PUT /api/v2/sensor/results/{id}` answered every CTIS validation failure with one item error, an empty
  pointer and "the value is not allowed here"; the reason was only in the server log. The 422 now lists one
  item error per problem, with the JSON pointer of the member (for example `/assets/29/technical/identity/kind`,
  `/tool/techniques/0`) and a code (`required`, `too_many`, `invalid_value`) with its fixed detail. Details
  still never quote the document.
- Docs: server/docs/architecture/sensors.md
