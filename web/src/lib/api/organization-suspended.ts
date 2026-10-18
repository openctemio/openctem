/**
 * The organization is suspended by the platform operator.
 *
 * The API answers every request of a suspended organization (any
 * credential) with `403 {code: "ORGANIZATION_SUSPENDED"}`. It is not a
 * permission the user can ask for, so it gets its own message, raised once by
 * the shared API client however many requests fail
 * (api/docs/architecture/organization-suspension.md).
 */

import { toast } from 'sonner'
import { getDictionary, translate } from '@/lib/i18n'

export const ORGANIZATION_SUSPENDED_CODE = 'ORGANIZATION_SUSPENDED'

/** Stable toast id: many requests fail at once, the user should see one toast. */
const TOAST_ID = 'organization-suspended'

export function isOrganizationSuspended(
  err: { statusCode?: number; code?: string } | null | undefined
): boolean {
  return !!err && err.statusCode === 403 && err.code === ORGANIZATION_SUSPENDED_CODE
}

/** The member-facing message in the page's language. */
export function organizationSuspendedMessage(): string {
  const locale = typeof document === 'undefined' ? undefined : document.documentElement.lang
  return translate(
    getDictionary(locale),
    'auth.organizationSuspended.message',
    'This organization is suspended — contact support'
  )
}

/** Shows the suspension message once, however many requests were refused. */
export function notifyOrganizationSuspended(): void {
  if (typeof window === 'undefined') return
  const locale = document.documentElement.lang
  toast.error(
    translate(getDictionary(locale), 'auth.organizationSuspended.title', 'Organization suspended'),
    { id: TOAST_ID, description: organizationSuspendedMessage() }
  )
}
