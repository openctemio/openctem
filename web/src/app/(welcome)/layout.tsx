import { cookies } from 'next/headers'

import { AccountShell } from '@/features/account/components/account-shell'
import { env } from '@/lib/env'

/**
 * The account space (api RFC-141): the slim shell, no tenant providers. The
 * pages under it call only the routes an account-only session may reach.
 */
export default async function WelcomeLayout({ children }: { children: React.ReactNode }) {
  const jar = await cookies()
  // With only a refresh token the hub starts the account session first.
  const sessionReady = !!jar.get(env.cookies.accountOnly)?.value
  return <AccountShell sessionReady={sessionReady}>{children}</AccountShell>
}
