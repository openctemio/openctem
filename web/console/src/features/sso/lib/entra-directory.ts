// The API accepts an organization's Entra ID provider only when its
// Directory (Tenant) ID is the directory's GUID: common, organizations,
// consumers or a domain name would accept accounts of other directories or
// never match the token's tid, so sign-in through the provider is refused
// (it shows as "SSO not configured" to the user). Same shape as the API check.
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export function isEntraDirectoryId(value: string | undefined | null): boolean {
  return GUID.test((value ?? '').trim())
}

/** A saved Entra ID provider that sign-in refuses until its directory id is fixed. */
export function entraNeedsDirectoryId(
  provider: string,
  tenantIdentifier: string | undefined | null
): boolean {
  return provider === 'entra_id' && !isEntraDirectoryId(tenantIdentifier)
}
