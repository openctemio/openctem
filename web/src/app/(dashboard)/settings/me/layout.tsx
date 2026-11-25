'use client'

import { usePathname } from 'next/navigation'
import { SettingsPage } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { activeSettingsItem } from '@/config/settings-nav'

/**
 * Your membership (/settings/me/*): the signed-in person inside this
 * organization (their role, notifications, activity, connected applications,
 * leaving). It needs no role, and it is organization data, so it lives in the
 * organization's settings and uses the organization's session; the person's
 * own account (profile, security, preferences) is the account area. The
 * settings rail ("Your membership" group) is the navigation; the header is the
 * current item's title and description from src/config/settings-nav.ts.
 * It is the shared settings frame (SettingsPage): the header and one column
 * at the settings reading width, sections divided by hairlines.
 */
export default function MembershipLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const { t } = useTranslation()
  const item = activeSettingsItem(pathname)

  return (
    <SettingsPage
      title={
        item
          ? t(`settings.item.${item.id}`, item.title)
          : t('settings.group.membership', 'Your membership')
      }
      description={item ? t(`settings.desc.${item.id}`, item.description) : undefined}
    >
      {children}
    </SettingsPage>
  )
}
