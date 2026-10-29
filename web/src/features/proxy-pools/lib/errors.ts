import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'

import type { Tr } from '@/features/sensors/lib/format'

/** The API's code for a proxy request error, from the error or its body. */
export function proxyErrorCode(err: unknown): string | undefined {
  if (!(err instanceof ApiClientError)) return undefined
  const fromDetails = (err.details as { code?: unknown } | undefined)?.code
  return typeof fromDetails === 'string' ? fromDetails : err.code
}

/** A bad line in the paste list: the server's message names the line. */
export function isInvalidEndpointError(err: unknown): boolean {
  return proxyErrorCode(err) === 'INVALID_PROXY_ENDPOINT'
}

/** A pool that sensors still use cannot be deleted. */
export function isPoolInUseError(err: unknown): boolean {
  if (proxyErrorCode(err) === 'PROXY_POOL_IN_USE') return true
  return err instanceof ApiClientError && err.statusCode === 409
}

/** A pool can be tested once a minute: the API answers 429. */
export function isRateLimitedError(err: unknown): boolean {
  return err instanceof ApiClientError && err.statusCode === 429
}

/** What to show for a failed pool request. */
export function describeProxyError(err: unknown, t: Tr, fallback: string): string {
  if (isPoolInUseError(err)) {
    return t(
      'proxyPools.error.inUse',
      'Sensors still use this pool. Set those sensors to another network path (or Direct) on their pages, then delete the pool.'
    )
  }
  if (isInvalidEndpointError(err)) {
    return `${getErrorMessage(err, fallback)} ${t(
      'proxyPools.error.invalidEndpointHint',
      'Fix the line and save again. Format: scheme://user:pass@host:port#label'
    )}`
  }
  return getErrorMessage(err, fallback)
}
