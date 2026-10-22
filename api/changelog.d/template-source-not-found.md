### Behaviour change: another organization's template source answers 404

- `GET`, `PUT` and `DELETE /api/v1/template-sources/{id}` (and enable, disable and sync) answered 403 "source belongs to another tenant" for another organization's template source and 404 for an unknown id, so a caller could tell that an id exists elsewhere. The source is now loaded within the caller's organization, and both cases answer the same 404.
