import { humanizeIdentifier } from '@/lib/humanize-identifier'

/**
 * Display names of the identity providers a person can sign in with: the
 * organization SSO providers (`identity_providers.provider`) and the account
 * sign-in methods (`users.auth_provider`). One map for every place the
 * console names a provider, so an id such as "google_workspace" is never
 * shown as is.
 */
const IDENTITY_PROVIDER_LABELS: Record<string, string> = {
  // Organization SSO providers (server/pkg/domain/identityprovider)
  entra_id: 'Microsoft Entra ID',
  okta: 'Okta',
  google_workspace: 'Google Workspace',
  // Account sign-in methods (server/pkg/domain/user)
  local: 'Email and password',
  google: 'Google',
  github: 'GitHub',
  microsoft: 'Microsoft',
  oidc: 'Single sign-on (OIDC)',
  saml: 'Single sign-on (SAML)',
}

/** Labels that are words, not product names: shown in the reader's language. */
const TRANSLATED_KEYS: Record<string, string> = {
  local: 'auth.provider.local',
  oidc: 'auth.provider.oidc',
  saml: 'auth.provider.saml',
}

type Translate = (key: string, fallback: string) => string

/**
 * "google_workspace" -> "Google Workspace"; an unknown id is humanized. Pass
 * `t` wherever the label is shown, so "Email and password" is translated.
 */
export function identityProviderLabel(
  provider: string | null | undefined,
  t?: Translate
): string {
  const id = provider || 'local'
  const key = TRANSLATED_KEYS[id]
  if (key && t) return t(key, IDENTITY_PROVIDER_LABELS[id])
  return IDENTITY_PROVIDER_LABELS[id] ?? humanizeIdentifier(id)
}
