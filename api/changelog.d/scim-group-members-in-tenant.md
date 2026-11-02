### Security: a SCIM group keeps only the organization's own members

- A SCIM client could put the id of any account on the platform into one of its organization's groups. Nothing was granted at once, but the stored row raised that person's role the day they joined the organization, and the stored id confirmed that the account existed.
- Create, replace and both member patches now keep only the organization's active members; other ids are dropped as if unknown. A failed membership lookup refuses the change.
