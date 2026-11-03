'use client'

import { useTranslation } from '@/context/i18n-provider'
import { TonePill } from '@/features/shared/components/tone-pill'

/** The platform statuses of an organization, in list-filter order. */
export const ORG_STATUSES = ['active', 'suspended', 'pending_deletion'] as const
export type OrgStatus = (typeof ORG_STATUSES)[number]

/** An organization's platform status as the shared state pill (text and icon). */
export function OrganizationStatePill({ status }: { status: string }) {
  const { t } = useTranslation()
  if (status === 'pending_deletion')
    return (
      <TonePill tone="destructive" label={t('admin.org.deletion.badge', 'Deletion scheduled')} />
    )
  if (status === 'suspended')
    return <TonePill tone="warning" label={t('admin.org.suspension.badge', 'Suspended')} />
  return <TonePill tone="success" label={t('admin.org.status.active', 'Active')} />
}
