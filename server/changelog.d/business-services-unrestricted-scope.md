### Fixed: the business services list no longer fails for administrators in organizations with private programs

- `GET /business-services` answered 500 (and editing a service or listing its assets answered 404) for an administrator or full-data role from whom private program assets are hidden: the visibility query was sent the arguments of the asset count it did not contain. Each query now gets only the arguments it uses. Who sees which service is unchanged: a restricted reader still sees only services linked to an asset in their scope, and another organization's service still answers 404.
- Docs: none (a query fix; the documented visibility rules are unchanged)
