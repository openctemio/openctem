### Security: asset services list and create check the caller's data scope in the handler

- `GET` and `POST /api/v1/assets/{id}/services` now check that the asset is inside the caller's data scope in the handler itself and answer 404 when it is not, as the by-id service routes already did. The route-level data-scope guard already refused these requests; the handler check keeps them safe wherever the routes are mounted.
- New tests walk every registered `/api/v1/assets/{id}/...` route as a data-scoped member against an out-of-scope asset and require 404, so a sub-resource route mounted without the guard fails CI.
