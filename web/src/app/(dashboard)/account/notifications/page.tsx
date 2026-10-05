'use client'

import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Bell, AlertTriangle, Save, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ErrorState } from '@/features/shared'
import {
  useNotificationPreferencesApi,
  updateNotificationPreferences,
  invalidatePreferencesCache,
  type NotificationPreferences,
} from '@/features/notifications/api/use-notification-api'
import { NOTIFICATION_TYPES } from '@/features/notifications/lib/notification-types'

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
 */
export default function NotificationsSettingsPage() {
  const [isSaving, setIsSaving] = useState(false)
  const { data: preferences, isLoading, error, mutate } = useNotificationPreferencesApi()

  // Local editing state, initialised from the API.
  const [inAppEnabled, setInAppEnabled] = useState(true)
  const [mutedTypes, setMutedTypes] = useState<string[]>([])
  const [minSeverity, setMinSeverity] = useState('info')
  const [dirty, setDirty] = useState(false)

  useEffect(() => {
    if (preferences) {
      setInAppEnabled(preferences.in_app_enabled)
      setMutedTypes(preferences.muted_types ?? [])
      setMinSeverity(preferences.min_severity)
      setDirty(false)
    }
  }, [preferences])

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
      }
      await updateNotificationPreferences(update)
      await invalidatePreferencesCache()
      setDirty(false)
      toast.success('Notification settings saved')
    } catch {
      toast.error('Failed to save notification settings')
    } finally {
      setIsSaving(false)
    }
  }

  if (isLoading) {
    return (
      <div className="grid gap-6">
        <Skeleton className="h-32 w-full" />
        <Skeleton className="h-32 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    )
  }

  if (error && !preferences) {
    return (
      <ErrorState
        title="notification settings"
        error={error}
        onRetry={() => {
          void mutate()
        }}
      />
    )
  }

  return (
    <div className="grid gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bell className="h-5 w-5" />
            In-app notifications
          </CardTitle>
          <CardDescription>The bell in the top bar.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between gap-4">
            <div>
              <Label htmlFor="in-app-enabled">Show in-app notifications</Label>
              <p className="text-sm text-muted-foreground">{inAppEnabled ? 'On' : 'Off'}</p>
            </div>
            <Switch
              id="in-app-enabled"
              checked={inAppEnabled}
              onCheckedChange={edit(setInAppEnabled)}
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5" />
            Severity filter
          </CardTitle>
          <CardDescription>Only notify me at or above this severity.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <Label htmlFor="min-severity">Minimum severity</Label>
              <p className="text-sm text-muted-foreground">Lower severities are left out</p>
            </div>
            <Select value={minSeverity} onValueChange={edit(setMinSeverity)}>
              <SelectTrigger id="min-severity" className="w-[180px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="info">Info (all)</SelectItem>
                <SelectItem value="low">Low and above</SelectItem>
                <SelectItem value="medium">Medium and above</SelectItem>
                <SelectItem value="high">High and above</SelectItem>
                <SelectItem value="critical">Critical only</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bell className="h-5 w-5" />
            Notification types
          </CardTitle>
          <CardDescription>Turn individual kinds of notification on or off.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {NOTIFICATION_TYPES.map((notifType, index) => {
              const isMuted = mutedTypes.includes(notifType.id)
              return (
                <div key={notifType.id}>
                  {index > 0 && <Separator className="mb-4" />}
                  <div className="flex items-center justify-between gap-4">
                    <div>
                      <Label htmlFor={`type-${notifType.id}`}>{notifType.name}</Label>
                      <p className="text-sm text-muted-foreground">{notifType.description}</p>
                    </div>
                    <Switch
                      id={`type-${notifType.id}`}
                      checked={!isMuted}
                      onCheckedChange={() => toggleMutedType(notifType.id)}
                      disabled={!inAppEnabled}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-end">
        <Button onClick={handleSave} disabled={!dirty || isSaving}>
          {isSaving ? (
            <Loader2 className="me-2 h-4 w-4 animate-spin" />
          ) : (
            <Save className="me-2 h-4 w-4" />
          )}
          {isSaving ? 'Saving…' : 'Save changes'}
        </Button>
      </div>
    </div>
  )
}
