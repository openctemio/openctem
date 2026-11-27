'use client'

import { usePathname } from 'next/navigation'

import { PageHeader, PageStack } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { activeAccountItem } from '@/config/account-nav'

/**
 * Account pages: the header is the current item's title and description from
 * src/config/account-nav.ts, the same words as the account navigation. The
 * page is the settings family's (SettingsPage): one column of flat sections at
 * the reading width, so a page never repeats this header in a card of its own.
 */
export default function AccountPagesLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const { t } = useTranslation()
  const item = activeAccountItem(pathname)

  return (
    <PageStack>
      <PageHeader
        title={
          item
            ? t(`account.area.nav.${item.id}`, item.title)
            : t('account.area.title', 'Your account')
        }
        description={item ? t(`account.area.desc.${item.id}`, item.description) : undefined}
        className="w-full max-w-settings"
      />
      <div data-slot="settings-column" className="flex min-w-0 max-w-settings flex-col gap-section">
        {children}
      </div>
    </PageStack>
  )
}
