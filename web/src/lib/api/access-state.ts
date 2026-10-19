/**
 * Why a read failed, as the person needs to hear it. A 403 is either a
 * module the organization has switched off (MODULE_NOT_ENABLED) or a missing
 * permission (any other 403); everything else is a failure worth retrying.
 * A data-scope refusal never arrives here (it is a 404).
 */
export type AccessState = 'module_off' | 'no_access' | 'failed'

export function accessStateOf(error: unknown): AccessState | undefined {
  if (!error) return undefined
  const e = error as { statusCode?: unknown; code?: unknown }
  if (e.statusCode === 403) {
    return e.code === 'MODULE_NOT_ENABLED' ? 'module_off' : 'no_access'
  }
  return 'failed'
}

/** The `details` of an API error (names the missing grant on a 403). */
export function errorDetails(error: unknown): unknown {
  return (error as { details?: unknown } | undefined)?.details
}
