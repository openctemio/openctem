'use client'

import { useTranslation } from '@/context/i18n-provider'
import { FilterSelect } from '@/features/shared'

export type AuditKind = 'changes' | 'all'

/** The kind a list filter value stands for: "all" or, by default, changes. */
export function auditKind(value: string | undefined): AuditKind {
  return value === 'all' ? 'all' : 'changes'
}

/**
 * Changes or all events, for every list of administrator audit rows (Admin
 * activity, an organization's Activity tab): the shared filter token, one
 * value always chosen. Changes is the default: page views and the record
 * written before each change stay in the chain, one click away.
 */
export function AuditKindLens({
  value,
  onChange,
}: {
  value: AuditKind
  onChange: (value: AuditKind) => void
}) {
  const { t } = useTranslation()
  return (
    <FilterSelect<AuditKind>
      label={t('admin.activity.kindLabel', 'Which events')}
      value={value}
      clearable={false}
      onChange={(v) => onChange(auditKind(v))}
      options={[
        { value: 'changes', label: t('admin.activity.kindChanges', 'Changes') },
        { value: 'all', label: t('admin.activity.kindAll', 'All events') },
      ]}
    />
  )
}
