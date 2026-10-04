# List query contract

How list, stats, groups, search and export endpoints read their filters. The
design, its evidence and the owner decisions are in
[RFC-048](../rfcs/RFC-048-list-query-contract.md).

## The rule

Every migrated collection endpoint parses its filter through
`pkg/filterspec` against the resource's field registry and compiles it with
`filterspec.Compile`. Nothing else builds a WHERE clause from request input.

```
GET  /api/v1/findings?severity=critical,high&epss_score_gte=0.1&q=log4j&sort=-priority_class
POST /api/v1/findings/search   {"v":1,"filter":{"all":[…]},"sort":["-epss_score"]}
```

Both decode into the same `filterspec.Spec`. `Compile` always prepends the
tenant predicate and, for a restricted caller, the data-scope predicate.

## Adding a filterable field

1. Add a `filterspec.Field` to the resource registry with:
   - `Name`: singular snake_case, equal to the response field, not ending in
     an operator suffix;
   - `Type` and `Ops`: only the operators the field supports;
   - `SQL`: a constant column or expression. Never build it from input;
   - `Indexed`: true only when an index backs range or `in` filters;
   - `Permission` when the field is not visible to every reader.
2. If the field is computed from another table, its SQL is a subquery that
   carries `tenant_id = <outer>.tenant_id` itself.
3. Add an index in the same PR if the table is large, with an `EXPLAIN` in the
   PR description.
4. The registry test fails on suffix-ending names, missing enums or ops the
   type cannot support.

## Actors

| Constructor | When | Effect |
|---|---|---|
| `filterspec.UserActor(tenantID, scope)` | any request; `scope` comes from `datascope.Enforcer.Resolve` | tenant + data scope (nil scope = unrestricted caller) |
| `filterspec.SystemActor(tenantID, reason)` | background jobs that produce admin-only output | tenant only; call sites are allowlisted |

There is no constructor without a tenant.

## Errors

A bad filter is `400` with code `INVALID_FILTER` and `details[]` naming the
`param` (GET) or JSON `path` (POST). Free-text values are never echoed.

## Unknown params and aliases

- During an endpoint's first release on the contract, unknown params are
  ignored but logged by name, counted in `filter_unknown_param_total`, and
  answered with `Deprecation` and `Warning` headers. Then the endpoint
  switches to strict (400).
- Old names (`severities`, `search`, …) are aliases: they work, answer with
  `Deprecation`/`Sunset` and count in `deprecated_query_param_requests_total`.

## Limits

50 leaves, depth 3, 100 values per list (500 for id fields in POST), 200
characters per value (`q` 255), 32 KB POST body.
