import { humanizeIdentifier } from '@/lib/humanize-identifier'
import type { useTranslation } from '@/context/i18n-provider'

type Translate = ReturnType<typeof useTranslation>['t']

// A key the catalogs do not know returns this fallback unchanged.
const MISSING = '\u0000'

function label(t: Translate, namespace: string, value: string): string {
  const found = t(`${namespace}.${value}`, MISSING)
  return found !== MISSING ? found : humanizeIdentifier(value)
}

/**
 * How a person or a session signs in: one name everywhere ("local" is a
 * password, "oidc" and "idp" are single sign-on), in the console language.
 * Keys admin.authProvider.<value>; an unknown value reads as its words.
 */
export function authProviderLabel(t: Translate, value: string): string {
  return label(t, 'admin.authProvider', value)
}

/** A person's role in an organization (admin.memberRole.<value>). */
export function memberRoleLabel(t: Translate, value: string): string {
  return label(t, 'admin.memberRole', value)
}

/** An account or membership status (admin.accountStatus.<value>). */
export function accountStatusLabel(t: Translate, value: string): string {
  return label(t, 'admin.accountStatus', value)
}
