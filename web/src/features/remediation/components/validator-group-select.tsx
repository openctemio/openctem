'use client'

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useGroups } from '@/features/access-control/api/use-groups'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'

const NONE = '__none__'

interface ValidatorGroupSelectProps {
  /** The campaign's validator group id (assigned_team), '' when none. */
  value: string
  onChange: (groupId: string) => void
  disabled?: boolean
}

/**
 * Picks the group that verifies a task's fix (the campaign's assigned_team is
 * a group, never a user). Without permission to list groups it shows the
 * current value and cannot change it.
 */
export function ValidatorGroupSelect({ value, onChange, disabled }: ValidatorGroupSelectProps) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const canList = hasPermission(Permission.GroupsRead)
  const { groups, isLoading } = useGroups(undefined, canList)
  const current = groups.find((g) => g.id === value)

  return (
    <Select
      value={value || NONE}
      onValueChange={(v) => onChange(v === NONE ? '' : v)}
      disabled={disabled || !canList || isLoading}
    >
      <SelectTrigger
        className="h-8"
        aria-label={t('remediationTasks.validator.label', 'Validator group')}
      >
        <SelectValue placeholder={t('remediationTasks.validator.placeholder', 'Choose a group')}>
          {value
            ? (current?.name ?? t('remediationTasks.validator.unknown', 'A group'))
            : t('remediationTasks.validator.none', 'No validator')}
        </SelectValue>
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={NONE}>{t('remediationTasks.validator.none', 'No validator')}</SelectItem>
        {groups.map((g) => (
          <SelectItem key={g.id} value={g.id}>
            {g.name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}
