/**
 * The account area (`app/(account)`): pages about the person, the same in
 * every organization, served only by the account routes of the API. It has
 * its own shell and navigation, separate from the organization's settings
 * (`config/settings-nav.ts`), so it opens for anyone signed in, with or without
 * an organization.
 */

import { Building2, KeyRound, Settings2, UserRound, type LucideIcon } from 'lucide-react'

export interface AccountNavItem {
  id: 'profile' | 'security' | 'preferences' | 'organizations'
  url: string
  /** English fallback of `account.area.nav.<id>`. */
  title: string
  /** English fallback of `account.area.desc.<id>`. */
  description: string
  icon: LucideIcon
}

export const ACCOUNT_NAV: readonly AccountNavItem[] = [
  {
    id: 'profile',
    url: '/account',
    title: 'Profile',
    description: 'Your name and contact details.',
    icon: UserRound,
  },
  {
    id: 'security',
    url: '/account/security',
    title: 'Security',
    description: 'Password, two-factor authentication, sign-in methods and signed-in devices.',
    icon: KeyRound,
  },
  {
    id: 'preferences',
    url: '/account/preferences',
    title: 'Preferences',
    description: 'Theme, language and how findings views open.',
    icon: Settings2,
  },
  {
    id: 'organizations',
    url: '/account/organizations',
    title: 'Organizations',
    description: 'The organizations you belong to, your invitations and new organizations.',
    icon: Building2,
  },
]

/** The account page at `pathname` (exact, trailing slash ignored), if any. */
export function activeAccountItem(pathname: string | null): AccountNavItem | undefined {
  if (!pathname) return undefined
  const path = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname
  return ACCOUNT_NAV.find((item) => item.url === path)
}
