'use client'

import { StatusLozenge } from '@/components/ui/status-lozenge'
import { Tag } from '@/components/ui/tag'
import { useTranslation } from '@/context/i18n-provider'
import { suppressionStatusLabel, suppressionTypeLabel } from '../types'
import type { SuppressionStatus, SuppressionType } from '../types'
import { SUPPRESSION_STATUS_TONE, SUPPRESSION_TYPE_ICON } from '../lib/suppression-tone'

/** The approval state of an exception rule: the shared workflow lozenge. */
export function SuppressionStatusBadge({ status }: { status: SuppressionStatus }) {
  const { t } = useTranslation()
  const cfg = SUPPRESSION_STATUS_TONE[status]
  return (
    <StatusLozenge
      tone={cfg?.tone ?? 'closed'}
      icon={cfg?.icon}
      label={suppressionStatusLabel(status, t)}
      value={status}
    />
  )
}

/** The exception type: a plain tag with an icon. */
export function SuppressionTypeBadge({ type }: { type: SuppressionType }) {
  const { t } = useTranslation()
  return (
    <Tag variant="plain" icon={SUPPRESSION_TYPE_ICON[type]} label={suppressionTypeLabel(type, t)} />
  )
}
