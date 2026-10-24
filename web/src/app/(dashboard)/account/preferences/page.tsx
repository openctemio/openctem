'use client'

import { useTranslation } from '@/context/i18n-provider'
import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import { Palette, Globe, Clock, Calendar, Save, Loader2, RotateCcw } from 'lucide-react'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTheme } from 'next-themes'
import {
  usePreferences,
  useUpdatePreferences,
  getLocalPreferences,
  mergeLocalPreferences,
  SUPPORTED_TIMEZONES,
  DATE_FORMATS,
} from '@/features/account'
import type { UpdatePreferencesInput } from '@/features/account'
import { PageStack } from '@/features/shared'

const THEME_FALLBACK = { light: 'Light', dark: 'Dark', system: 'System' } as const

export default function PreferencesPage() {
  const { t } = useTranslation()
  const { theme, setTheme } = useTheme()
  const { preferences, isLoading, mutate } = usePreferences()
  const { updatePreferences, isUpdating } = useUpdatePreferences()

  // Form state
  const [formData, setFormData] = useState<UpdatePreferencesInput>({
    theme: 'system',
    language: 'en',
    timezone: 'UTC',
    date_format: 'DD/MM/YYYY',
    time_format: '24h',
  })
  const [hasChanges, setHasChanges] = useState(false)

  // Populate form when preferences load.
  // The backend only stores `theme` + `language`. The remaining fields
  // (timezone, date/time format) have no backend column, so they are
  // persisted in localStorage — otherwise a
  // Save followed by a reload would silently lose them. This mirrors the
  // browser-local Display Preferences on the General Settings page.
  useEffect(() => {
    if (preferences) {
      const local = getLocalPreferences() || {}
      setFormData({
        theme: preferences.theme || 'system',
        language: preferences.language || 'en',
        timezone: local.timezone || 'UTC',
        date_format: local.date_format || 'DD/MM/YYYY',
        time_format: local.time_format || '24h',
      })
      setHasChanges(false)
    }
  }, [preferences])

  // Sync theme with next-themes
  useEffect(() => {
    if (formData.theme && formData.theme !== theme) {
      // Only sync if different to avoid loops
    }
  }, [formData.theme, theme])

  // Handle field change
  const handleChange = <K extends keyof UpdatePreferencesInput>(
    field: K,
    value: UpdatePreferencesInput[K]
  ) => {
    setFormData((prev) => ({ ...prev, [field]: value }))
    setHasChanges(true)

    // Immediately apply theme change
    if (field === 'theme' && typeof value === 'string') {
      setTheme(value)
    }
  }

  // Save preferences.
  // Split the write: theme + language go to the server (the only fields it
  // persists); the display preferences are browser-local, so
  // they are written to localStorage. Sending the phantom fields to the API
  // was a no-op (silently dropped), which is the bug this fixes.
  const handleSave = async () => {
    try {
      // Merge: the same browser-local object also holds the desktop
      // notification choice, which /account/notifications owns.
      mergeLocalPreferences({
        timezone: formData.timezone,
        date_format: formData.date_format,
        time_format: formData.time_format,
      })
      await updatePreferences({
        theme: formData.theme,
        language: formData.language,
      })
      // Re-read the preferences from the server rather than caching the PUT
      // response: an older API returned the whole user object there, which
      // reset this form to its defaults (23a B4).
      await mutate()
      setHasChanges(false)
      toast.success(t('account.preferences.saved', 'Preferences saved'))
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('account.preferences.saveFailed', 'Could not save preferences'))
      )
    }
  }

  // Reset to defaults
  const handleReset = () => {
    const defaults: UpdatePreferencesInput = {
      theme: 'system',
      language: 'en',
      timezone: 'UTC',
      date_format: 'DD/MM/YYYY',
      time_format: '24h',
    }
    setFormData(defaults)
    setTheme('system')
    setHasChanges(true)
    toast.info(t('account.preferences.resetDone', 'Preferences reset to defaults (not saved yet)'))
  }

  // Loading state
  if (isLoading) {
    return (
      <PageStack>
        <Skeleton className="h-48 w-full" />
        <Skeleton className="h-48 w-full" />
        <Skeleton className="h-64 w-full" />
      </PageStack>
    )
  }

  return (
    <PageStack>
      {/* Appearance */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Palette className="h-5 w-5" />
            {t('account.preferences.appearance', 'Appearance')}
          </CardTitle>
          <CardDescription>
            {t(
              'settings.preferences.appearanceDescription',
              'Customize how {product} looks on your device'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label id="theme-label">{t('account.preferences.theme', 'Theme')}</Label>
            <div className="flex gap-2" role="group" aria-labelledby="theme-label">
              {(['light', 'dark', 'system'] as const).map((mode) => (
                <Button
                  key={mode}
                  variant={formData.theme === mode ? 'default' : 'outline'}
                  size="sm"
                  aria-pressed={formData.theme === mode}
                  onClick={() => handleChange('theme', mode)}
                  className="flex-1"
                >
                  {t(`account.preferences.theme.${mode}`, THEME_FALLBACK[mode])}
                </Button>
              ))}
            </div>
            <p className="text-xs text-muted-foreground">
              {formData.theme === 'system'
                ? t(
                    'account.preferences.theme.systemHint',
                    'Automatically switch based on your system settings'
                  )
                : formData.theme === 'dark'
                  ? t('account.preferences.theme.darkHint', 'Always use dark mode')
                  : t('account.preferences.theme.lightHint', 'Always use light mode')}
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Localization */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Globe className="h-5 w-5" />
            {t('account.preferences.localization', 'Localization')}
          </CardTitle>
          <CardDescription>
            {t(
              'account.preferences.localizationDescription',
              'Timezone and date format preferences'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-2">
            {/* Language is chosen from the user menu (the one picker that drives the
                interface); a second picker here changed nothing visible. */}
            {/* Timezone */}
            <div className="space-y-2">
              <Label htmlFor="timezone" className="flex items-center gap-2">
                <Clock className="h-4 w-4" />
                {t('account.preferences.timezone', 'Timezone')}
              </Label>
              <Select
                value={formData.timezone}
                onValueChange={(value) => handleChange('timezone', value)}
              >
                <SelectTrigger id="timezone">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SUPPORTED_TIMEZONES.map((tz) => (
                    <SelectItem key={tz.value} value={tz.value}>
                      {tz.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <Separator />

          <div className="grid gap-4 sm:grid-cols-2">
            {/* Date Format */}
            <div className="space-y-2">
              <Label htmlFor="date-format" className="flex items-center gap-2">
                <Calendar className="h-4 w-4" />
                {t('account.preferences.dateFormat', 'Date format')}
              </Label>
              <Select
                value={formData.date_format}
                onValueChange={(value) => handleChange('date_format', value)}
              >
                <SelectTrigger id="date-format">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {DATE_FORMATS.map((fmt) => (
                    <SelectItem key={fmt.value} value={fmt.value}>
                      {fmt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Time Format */}
            <div className="space-y-2">
              <Label htmlFor="time-format">
                {t('account.preferences.timeFormat', 'Time format')}
              </Label>
              <Select
                value={formData.time_format}
                onValueChange={(value) => handleChange('time_format', value as '12h' | '24h')}
              >
                <SelectTrigger id="time-format">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="24h">
                    {t('account.preferences.time24', '24-hour (14:30)')}
                  </SelectItem>
                  <SelectItem value="12h">
                    {t('account.preferences.time12', '12-hour (2:30 PM)')}
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Actions */}
      <div className="flex justify-between">
        <Button variant="outline" onClick={handleReset}>
          <RotateCcw className="me-2 h-4 w-4" />
          {t('account.preferences.reset', 'Reset to defaults')}
        </Button>
        <Button onClick={handleSave} disabled={!hasChanges || isUpdating}>
          {isUpdating ? (
            <Loader2 className="me-2 h-4 w-4 animate-spin" />
          ) : (
            <Save className="me-2 h-4 w-4" />
          )}
          {isUpdating
            ? t('account.saving', 'Saving...')
            : t('account.preferences.save', 'Save preferences')}
        </Button>
      </div>
    </PageStack>
  )
}
