# Calling the API from the Web Console

How web console code talks to the OpenCTEM API: the request path, the shared
client, SWR hooks, mutations and errors. Paths are relative to `web/`.

## Request path

```
Browser  fetch('/api/v1/...')                 relative, same origin
   -> src/app/api/v1/[...path]/route.ts       reads the httpOnly session cookie,
                                              forwards with Authorization: Bearer
   -> API (BACKEND_API_URL)
```

The browser never holds the access token and never needs an API URL. The only
setting is the server-side `BACKEND_API_URL` (see
[ENVIRONMENT_VARIABLES.md](../ops/ENVIRONMENT_VARIABLES.md)).

## Wire types

API request and response types are generated from the OpenAPI spec into
`src/lib/api/generated/api.types.ts` (not committed; `make generate` at the
repository root). Feature types (`src/lib/api/*-types.ts`,
`src/features/<name>/types/`) should derive from or match the generated ones; CI
type-checks the console against the spec a pull request produces.

## The client (`src/lib/api/client.ts`)

```ts
import { get, post, put, patch, del, uploadFile } from '@/lib/api/client'

const zones = await get<ScanZoneListResponse>('/api/v1/scan-zones')
const zone = await post<ScanZone>('/api/v1/scan-zones', body)
await del<void>(`/api/v1/scan-zones/${id}`)
```

The client:

- sends the session cookie (`credentials: 'include'`) and, on POST, PUT, PATCH
  and DELETE, the `X-CSRF-Token` header copied from the `csrf_token` cookie.
  A raw `fetch` to a mutating endpoint must add that header itself, or the API
  answers `403 csrf_token_missing_header`;
- on `401`, refreshes the session once and retries;
- on a step-up challenge (`STEP_UP_REQUIRED`), asks the user to re-authenticate
  and retries (`src/lib/api/step-up.ts`);
- throws `ApiClientError` (`code`, `statusCode`, `details`) for any error answer.

URL builders live in `src/lib/api/endpoints.ts` (`API_BASE` plus one
`<area>Endpoints` object per area, for example `scanZoneEndpoints.list()`). Use
them instead of hand-written paths.

## Reading data: SWR hooks

Each area has a hooks file (`src/lib/api/<area>-hooks.ts` or
`src/features/<name>/hooks/`). The pattern:

```ts
'use client'
import useSWR, { type SWRConfiguration } from 'swr'
import { get } from './client'
import { useTenant } from '@/context/tenant-provider'
import { scanZoneEndpoints } from './endpoints'

export function useScanZones(enabled = true, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  // No tenant or no permission: key null, so no request (and no 403).
  const key = currentTenant && enabled ? scanZoneEndpoints.list() : null
  return useSWR<ScanZoneListResponse>(key, (url: string) => get(url), config)
}
```

Rules:

- Use a **string key** built from the URL and query string, never an object.
- Pass `null` as the key when the user lacks the read permission or no
  organization is selected; gate with `usePermissions().can(...)`.
- Always paginate list calls (`page`, `per_page`); see
  `src/lib/api/fetch-all-pages.ts` when a screen truly needs every row.
- Helpers in `src/lib/api/hooks.ts`: `useDependentData` (fetch when a condition
  holds), `usePolling` (refresh interval), `optimisticUpdate`.

## Writing data

Mutations are plain async functions next to the hooks; after one, revalidate the
affected keys:

```ts
export function createScanZone(body: CreateScanZoneRequest) {
  return post<ScanZone>(scanZoneEndpoints.create(), body)
}

export async function invalidateScanZonesCache() {
  const { mutate } = await import('swr')
  await mutate((key) => typeof key === 'string' && key.startsWith(API_BASE.SCAN_ZONES))
}
```

In a component: call the function, then the invalidation (or the hook's
`mutate()`), and show the result with a `sonner` toast.

## Errors

```ts
import { handleApiError, extractValidationErrors, ApiClientError } from '@/lib/api/error-handler'

try {
  await createScanZone(values)
} catch (err) {
  if (err instanceof ApiClientError) {
    const fieldErrors = extractValidationErrors(err) // per-field messages for a 400/422
    if (fieldErrors) return setFormErrors(fieldErrors)
  }
  handleApiError(err, { showToast: true })
}
```

`handleApiError` maps API error codes to user-facing messages and hides internal
details of server errors. `retryWithBackoff` retries transient failures.

## Uploads

```ts
await uploadFile<Evidence>(url, file, {
  onProgress: ({ percentage }) => setProgress(percentage),
})
```

## Server Components

Server Components and Server Actions call the API on the server with
`BACKEND_API_URL` and the session cookie; see the auth helpers in
`src/features/auth/` and `src/lib/cookies-server.ts`.
