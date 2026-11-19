/**
 * Onboarding - Create Team Page
 *
 * Two contexts share this page:
 *   1. First-team onboarding (user has zero tenants, came from /login)
 *   2. Additional-team flow (user came from /select-tenant — they already
 *      have tenants but want to create another one)
 *
 * The two contexts are distinguished by the presence of the
 * `pendingTenants` cookie: if it's set, the user already has tenants and
 * we're in the additional-team flow. Heading copy and back-link adjust
 * accordingly. Both flows reuse `createFirstTeamAction` because that
 * action only requires the refresh_token, which both states have.
 *
 * When the installation lets only the platform administrator create
 * organizations (the admin_only sign-up policy), the form is replaced by a
 * notice to ask the administrator for access, with sign-out (TeamOnboarding).
 */

import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'
import { EntryActions, EntryCard } from '@/components/entry'
import { env } from '@/lib/env'
import { OnboardingLogout, TeamOnboarding } from '@/features/tenant'
import { BackToTeamsLink } from '@/features/auth/components/back-to-teams-link'

export default async function CreateFirstTeamPage() {
  // Check if user is authenticated (has refresh token)
  const cookieStore = await cookies()
  const refreshToken = cookieStore.get(env.auth.refreshCookieName)

  if (!refreshToken?.value) {
    // Not logged in - redirect to login
    redirect('/login')
  }

  // Check if user already has a team SELECTED (active tenant cookie).
  // If so, they're not in the unselected-tenant flow — bounce to dashboard.
  const tenantCookie = cookieStore.get(env.cookies.tenant)
  if (tenantCookie?.value) {
    redirect('/')
  }

  // Detect "additional team" context: user has pendingTenants cookie,
  // meaning they came from /select-tenant rather than from a fresh login
  // with zero tenants.
  const hasPendingTenants = !!cookieStore.get(env.cookies.pendingTenants)?.value

  // A first-time account (no organization at all) belongs in the account
  // space, which also lists invitations and the account pages.
  if (!hasPendingTenants) {
    redirect('/account/organizations')
  }

  return (
    <EntryCard>
      <TeamOnboarding hasOtherTeams={hasPendingTenants} />

      {/* Ways out, under the page's own actions. The back link shows only when
          the user came from /select-tenant (they have other teams to go back
          to); for first-team onboarding there is nowhere to go back to. */}
      <EntryActions>
        {hasPendingTenants && <BackToTeamsLink />}
        <OnboardingLogout />
      </EntryActions>
    </EntryCard>
  )
}
