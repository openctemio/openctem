### Added: the findings query language negates the state field

- `state` (open, fixed, dispositioned, closed, all) was already a findings field; `-state:closed` and `state!=open` now work in the short and long form, so the State chip of the findings list and a query say the same thing. A negation compiles to `NOT` of the same constant status predicate the list's state filter uses; no new query shape, the tenant condition is unchanged.
- Docs: https://github.com/openctemio/openctem/blob/develop/server/docs/architecture/query-language.md
