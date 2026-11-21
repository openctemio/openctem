'use client'

/**
 * How a notification channel groups similar alerts, shared by the add and
 * edit dialogs: alerts of the same kind about findings that arrive within
 * the window reach the channel as one message, and urgent alerts (critical
 * or known exploited) can still go out at once.
 */

import { useTranslation } from '@/context/i18n-provider'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

/** Window choices in minutes (the API accepts 1 to 60). */
export const GROUP_WINDOW_CHOICES = [1, 2, 5, 10, 15, 30, 60] as const

export const DEFAULT_GROUPING = {
  group_similar: true,
  group_window_minutes: 2,
  urgent_at_once: true,
} as const

export interface ChannelGrouping {
  group_similar: boolean
  group_window_minutes: number
  urgent_at_once: boolean
}

interface ChannelGroupingSettingsProps {
  idPrefix: string
  value: ChannelGrouping
  onChange: (next: Partial<ChannelGrouping>) => void
}

export function ChannelGroupingSettings({
  idPrefix,
  value,
  onChange,
}: ChannelGroupingSettingsProps) {
  const { t } = useTranslation()
  const choices: number[] = [...GROUP_WINDOW_CHOICES]
  if (!choices.includes(value.group_window_minutes)) {
    choices.push(value.group_window_minutes)
    choices.sort((a, b) => a - b)
  }
  return (
    <div className="space-y-3">
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <Label htmlFor={`${idPrefix}_group_similar`}>
            {t('notificationTypes.grouping.groupSimilar')}
          </Label>
          <p className="text-xs text-muted-foreground">
            {t('notificationTypes.grouping.groupSimilarHint')}
          </p>
        </div>
        <Switch
          id={`${idPrefix}_group_similar`}
          checked={value.group_similar}
          onCheckedChange={(v) => onChange({ group_similar: v })}
        />
      </div>

      <div className="flex items-center justify-between gap-4">
        <Label htmlFor={`${idPrefix}_group_window`}>{t('notificationTypes.grouping.window')}</Label>
        <Select
          value={String(value.group_window_minutes)}
          onValueChange={(v) => onChange({ group_window_minutes: Number(v) })}
          disabled={!value.group_similar}
        >
          <SelectTrigger id={`${idPrefix}_group_window`} className="h-8 w-[140px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {choices.map((m) => (
              <SelectItem key={m} value={String(m)}>
                {t('notificationTypes.grouping.minutes', '{count} min', { count: m })}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <Label htmlFor={`${idPrefix}_urgent_at_once`}>
            {t('notificationTypes.grouping.urgentAtOnce')}
          </Label>
          <p className="text-xs text-muted-foreground">
            {t('notificationTypes.grouping.urgentAtOnceHint')}
          </p>
        </div>
        <Switch
          id={`${idPrefix}_urgent_at_once`}
          checked={value.urgent_at_once}
          onCheckedChange={(v) => onChange({ urgent_at_once: v })}
          disabled={!value.group_similar}
        />
      </div>
    </div>
  )
}
