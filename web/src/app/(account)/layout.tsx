import { cookies } from 'next/headers'

import { AccountShell } from '@/features/account/components/account-shell'
import { env } from '@/lib/env'

/**
 * The account area: the person's own pages, outside the organization shell.
 * No tenant providers, sidebar, switcher, search or notifications mount here:
 * the pages call only the account routes of the API, so they render for any
 * signed-in person, including one an organization does not admit yet.
 */
export default async function AccountAreaLayout({ children }: { children: React.ReactNode }) {
  const jar = await cookies()
  const accountOnly = !!jar.get(env.cookies.accountOnly)?.value
  const organizationName = currentOrganizationName(jar.get(env.cookies.tenant)?.value)
  // With no organization open and no account session yet, the Organizations
  // page starts the account session first; nothing else reads the API before.
  const sessionReady = accountOnly || organizationName !== undefined
  return (
    <AccountShell sessionReady={sessionReady} organizationName={organizationName}>
      {children}
    </AccountShell>
  )
}

/** The open organization's display name from the tenant cookie, if one is open. */
function currentOrganizationName(raw: string | undefined): string | undefined {
  if (!raw) return undefined
  try {
    const parsed = JSON.parse(raw) as { name?: unknown; slug?: unknown }
    if (typeof parsed.name === 'string' && parsed.name) return parsed.name
    if (typeof parsed.slug === 'string' && parsed.slug) return parsed.slug
    return ''
  } catch {
    return undefined
  }
}
