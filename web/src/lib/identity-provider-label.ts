import { humanizeIdentifier } from '@/lib/humanize-identifier'

/**
 * Display names of the identity providers a person can sign in with: the
 * organization SSO providers (`identity_providers.provider`) and the account
 * sign-in methods (`users.auth_provider`). One map for every place the
 * console names a provider, so an id such as "google_workspace" is never
 * shown as is.
 */
const IDENTITY_PROVIDER_LABELS: Record<string, string> = {
  // Organization SSO providers (api/pkg/domain/identityprovider)
  entra_id: 'Microsoft Entra ID',
  okta: 'Okta',
  google_workspace: 'Google Workspace',
  // Account sign-in methods (api/pkg/domain/user)
  local: 'Email and password',
  google: 'Google',
  github: 'GitHub',
  microsoft: 'Microsoft',
  oidc: 'Single sign-on (OIDC)',
  saml: 'Single sign-on (SAML)',
}

/** "google_workspace" -> "Google Workspace"; an unknown id is humanized. */
export function identityProviderLabel(provider: string | null | undefined): string {
  if (!provider) return IDENTITY_PROVIDER_LABELS.local
  return IDENTITY_PROVIDER_LABELS[provider] ?? humanizeIdentifier(provider)
}
