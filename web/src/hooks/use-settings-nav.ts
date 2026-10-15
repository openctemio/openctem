'use client'

import { useMemo } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { useTenantModules } from '@/features/integrations/api/use-tenant-modules'
import useSWR from 'swr'
import { LIMITS_APPLY_KEY } from '@/context/bootstrap-session'
import { useNavItemAccess, subModuleStatus } from '@/lib/permissions'
import { settingsNav, type SettingsNavGroup, type SettingsNavItem } from '@/config/settings-nav'

export interface VisibleSettingsItem extends SettingsNavItem {
  /** Translated title. */
  label: string
  /** Translated description. */
  desc: string
  /** Translated group title. */
  groupLabel: string
}

export interface VisibleSettingsGroup extends Omit<SettingsNavGroup, 'items'> {
  label: string
  items: VisibleSettingsItem[]
}

/**
 * The settings groups and items the current user may open, translated.
 *
 * An item is hidden when the user lacks its permission, or its module (or
 * integration sub-module) is off for the tenant: the same decision the main
 * sidebar makes (useNavItemAccess, subModuleStatus). A group with no visible
 * item is dropped. "My account" items carry no permission, so every signed-in
 * user sees at least that group. An item marked onlyWhenLimitsApply (Usage &
 * limits) is listed only while a limit or a module deny applies to the
 * organization: the session bootstrap says so (limits_apply, owners and
 * admins), so no page load asks for the limits.
 */
export function useSettingsNav(): VisibleSettingsGroup[] {
  const canSee = useNavItemAccess()
  const { subModules } = useTenantModules()
  const { t } = useTranslation()
  // Cache only (null fetcher): the bootstrap seeds it; nothing is fetched.
  const { data: limitsApply = false } = useSWR<boolean>(LIMITS_APPLY_KEY, null, {
    revalidateOnFocus: false,
    revalidateIfStale: false,
  })

  return useMemo(
    () =>
      settingsNav
        .map((group) => {
          const label = t(`settings.group.${group.id}`, group.title)
          const items = group.items
            .filter(
              (item) =>
                canSee(item) &&
                (!item.onlyWhenLimitsApply || limitsApply) &&
                subModuleStatus(item.module, item.subModuleKey, subModules) !== false
            )
            .map((item) => ({
              ...item,
              label: t(`settings.item.${item.id}`, item.title),
              desc: t(`settings.desc.${item.id}`, item.description),
              groupLabel: label,
            }))
          return { ...group, label, items }
        })
        .filter((group) => group.items.length > 0),
    [canSee, subModules, t, limitsApply]
  )
}
