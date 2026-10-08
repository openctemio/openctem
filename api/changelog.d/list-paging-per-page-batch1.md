### Changed: more lists page with `page` and `per_page`

- These lists now read `per_page` instead of `page_size`, through the shared
  parser:
  - `GET /api/v1/credentials`, `/credentials/identities` and
    `/credentials/identities/{identity}/exposures`;
  - `GET /api/v1/findings/{id}/activities`;
  - the notification outbox list;
  - the secret store credentials;
  - the template sources.
- A `page` or `per_page` that is not a positive whole number is answered 400.
  It used to fall back silently to the first page of 20. `per_page` is capped
  at 100; a larger value used to fall back to 20.
- **Behaviour change:** clients that send `page_size` get the default page size
  until they send `per_page`. The console is updated.
