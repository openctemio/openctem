import { AdminApiError } from '../api/admin-client'
import { WebAuthnCancelledError, WebAuthnUnsupportedError } from './webauthn'

type Translate = (key: string, fallback: string, vars?: Record<string, string | number>) => string

/**
 * What a failed security-key ceremony tells the administrator: a dismissed or
 * timed-out browser prompt, an unsupported browser and the console's own
 * refusals get words of their own; anything else shows the API's message.
 */
export function securityKeyErrorMessage(err: unknown, t: Translate): string {
  if (err instanceof WebAuthnCancelledError)
    return t(
      'admin.keys.cancelled',
      'The security key prompt was closed or timed out. Try again when you are ready.'
    )
  if (err instanceof WebAuthnUnsupportedError)
    return t(
      'admin.keys.unsupported',
      'This browser cannot use security keys or passkeys. Use a current browser.'
    )
  if (err instanceof DOMException && err.name === 'InvalidStateError')
    return t('admin.keys.alreadyRegistered', 'This security key is already registered.')
  if (err instanceof AdminApiError) {
    if (err.status === 429)
      return t('admin.keys.tooMany', 'Too many attempts. Wait a minute and try again.')
    if (err.code === 'WEBAUTHN_UNAVAILABLE')
      return t(
        'admin.keys.notConfigured',
        'Security keys are not available: the console address (ADMIN_PUBLIC_URL) is not set.'
      )
    if (err.code === 'WEBAUTHN_KEEP_REQUIRED')
      return t(
        'admin.keys.keepRequired',
        'The console requires at least two security keys. Register a replacement before removing this one.'
      )
    if (err.message) return err.message
  }
  return t('admin.keys.failed', 'The security key could not be used. Try again.')
}
