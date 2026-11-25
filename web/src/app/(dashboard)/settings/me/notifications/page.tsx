'use client'

import { useCallback, useEffect, useState } from 'react'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { toast } from 'sonner'
import {
  ErrorState,
  SettingsRow,
  SettingsSaveBar,
  SettingsSection,
  SettingsSwitchRow,
} from '@/features/shared'
import {
  useNotificationPreferencesApi,
  updateNotificationPreferences,
  invalidatePreferencesCache,
  type NotificationPreferences,
} from '@/features/notifications/api/use-notification-api'
import { NOTIFICATION_TYPES } from '@/features/notifications/lib/notification-types'
import { SEVERITY_LEVELS, type SeverityLevel } from '@/lib/severity'
import { useTranslation } from '@/context/i18n-provider'

/** Threshold wording per level (the list runs least severe first). */
const MIN_SEVERITY_FALLBACK: Record<SeverityLevel, string> = {
  info: 'Info (all)',
  low: 'Low and above',
  medium: 'Medium and above',
  high: 'High and above',
  critical: 'Critical only',
}

/**
 * The user's own notification settings: the one place for them, saved on the
 * server (PUT /api/v1/notifications/preferences, user-scoped, no permission).
 *
 * Only controls that do something are shown: the e-mail digest and desktop
 * notifications have no sender yet and are hidden until they do (settings
 * decisions: no control without a consumer). The stored digest value is left
 * as it is.
 *
 * Organization-wide channels (Slack, Teams, webhooks) are configured under
 * Settings > Integrations > Notification channels.
 *
 * Layout: the shared settings frame (the /settings/me layout), two flat
 * sections divided by hairlines (what reaches you, and which kinds), one row
 * per setting, the save bar only while something changed.
 */
export default function NotificationsSettingsPage() {
  const { t } = useTranslation()
  const [isSaving, setIsSaving] = useState(false)
  const { data: preferences, isLoading, error, mutate } = useNotificationPreferencesApi()

  // Local editing state, initialised from the API.
  const [inAppEnabled, setInAppEnabled] = useState(true)
  const [mutedTypes, setMutedTypes] = useState<string[]>([])
  const [minSeverity, setMinSeverity] = useState('info')
  const [autoWatch, setAutoWatch] = useState(true)
  const [dirty, setDirty] = useState(false)

  // The saved values: on load, after a save and on Discard.
  const reset = useCallback(() => {
    if (!preferences) return
    setInAppEnabled(preferences.in_app_enabled)
    setMutedTypes(preferences.muted_types ?? [])
    // An empty or unknown stored value reads as the lowest threshold.
    setMinSeverity(
      SEVERITY_LEVELS.includes(preferences.min_severity as SeverityLevel)
        ? preferences.min_severity
        : 'info'
    )
    setAutoWatch(preferences.auto_watch ?? true)
    setDirty(false)
  }, [preferences])
  useEffect(reset, [reset])

  const edit =
    <T,>(set: (v: T) => void) =>
    (v: T) => {
      set(v)
      setDirty(true)
    }

  const toggleMutedType = (typeId: string) => {
    setMutedTypes((prev) =>
      prev.includes(typeId) ? prev.filter((t) => t !== typeId) : [...prev, typeId]
    )
    setDirty(true)
  }

  const handleSave = async () => {
    setIsSaving(true)
    try {
      const update: Partial<NotificationPreferences> = {
        in_app_enabled: inAppEnabled,
        muted_types: mutedTypes,
        min_severity: minSeverity,
        auto_watch: autoWatch,
      }
      await updateNotificationPreferences(update)
      await invalidatePreferencesCache()
      setDirty(false)
      toast.success(t('account.notifications.saved', 'Notification settings saved'))
    } catch {
      toast.error(t('account.notifications.saveFailed', 'Could not save notification settings'))
    } finally {
      setIsSaving(false)
    }
  }

  if (isLoading) {
    return (
      <div className="flex flex-col gap-3" aria-busy="true">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    )
  }

  if (error && !preferences) {
    return (
      <ErrorState
        title={t('account.notifications.errorSubject', 'notification settings')}
        error={error}
        onRetry={() => {
          void mutate()
        }}
      />
    )
  }

  return (
    <>
      <SettingsSection
        framed
        id="in-app"
        title={t('account.notifications.inApp', 'In-app notifications')}
        description={t('account.notifications.inAppHint', 'The bell in the top bar.')}
      >
        <SettingsSwitchRow
          id="in-app-enabled"
          label={t('account.notifications.inAppShow', 'Show in-app notifications')}
          checked={inAppEnabled}
          onCheckedChange={edit(setInAppEnabled)}
        />
        <SettingsRow
          wide
          labelId="min-severity-label"
          label={t('account.notifications.minSeverity', 'Minimum severity')}
          hint={t(
            'account.notifications.severityFilterHint',
            'Only notify me at or above this severity.'
          )}
        >
          <Select value={minSeverity} onValueChange={edit(setMinSeverity)}>
            <SelectTrigger
              id="min-severity"
              aria-labelledby="min-severity-label"
              className="w-full"
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {[...SEVERITY_LEVELS].reverse().map((s) => (
                <SelectItem key={s} value={s}>
                  {t(`account.notifications.min.${s}`, MIN_SEVERITY_FALLBACK[s])}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </SettingsRow>
        <SettingsSwitchRow
          id="auto-watch"
          label={t('notificationTypes.autoWatch.label', 'Watch what I take part in')}
          hint={t(
            'notificationTypes.autoWatch.description',
            'Starts when you comment, change a status, claim a fix or are assigned. Unwatching one item sticks.'
          )}
          checked={autoWatch}
          onCheckedChange={edit(setAutoWatch)}
        />
      </SettingsSection>

      <SettingsSection
        framed
        id="notification-types"
        title={t('notificationTypes.title', 'Notification types')}
        description={t('notificationTypes.subtitle', 'Turn each kind on or off.')}
      >
        {NOTIFICATION_TYPES.map((notifType) => (
          <SettingsSwitchRow
            key={notifType.id}
            id={`type-${notifType.id}`}
            label={t(`notificationTypes.${notifType.id}.name`, notifType.name)}
            hint={
              notifType.description
                ? t(`notificationTypes.${notifType.id}.description`, notifType.description)
                : undefined
            }
            checked={!mutedTypes.includes(notifType.id)}
            onCheckedChange={() => toggleMutedType(notifType.id)}
            // The digest also comes by email, so it can be muted with
            // in-app notifications off.
            disabled={!inAppEnabled && notifType.id !== 'finding_approval_digest'}
          />
        ))}
      </SettingsSection>

      <SettingsSaveBar
        dirty={dirty}
        saving={isSaving}
        onSave={() => void handleSave()}
        onDiscard={reset}
      />
    </>
  )
}
