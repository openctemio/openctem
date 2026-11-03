import { AccountShell } from '@/features/account/components/account-shell'

/**
 * The account space (api RFC-141): the slim shell, no tenant providers. The
 * pages under it call only the routes an account-only session may reach.
 */
export default function WelcomeLayout({ children }: { children: React.ReactNode }) {
  return <AccountShell>{children}</AccountShell>
}
