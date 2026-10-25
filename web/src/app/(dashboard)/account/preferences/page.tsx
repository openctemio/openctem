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
import { Skeleton } from '@/components/ui/skeleton'
import { Palette, Save, Loader2, RotateCcw, Bug } from 'lucide-react'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTheme } from 'next-themes'
import { usePreferences, useUpdatePreferences } from '@/features/account'
import type { FindingsInformationalPreference, UpdatePreferencesInput } from '@/features/account'
import { refreshFindingQuickViews } from '@/features/findings/api/use-quick-views'
import { PageStack } from '@/features/shared'

const THEME_FALLBACK = { light: 'Light', dark: 'Dark', system: 'System' } as const

const INFORMATIONAL_CHOICES: ReadonlyArray<{
  value: FindingsInformationalPreference
  fallback: string
}> = [
  { value: 'default', fallback: "Organization's default" },
  { value: 'exclude', fallback: 'Hide informational findings' },
  { value: 'include', fallback: 'Show informational findings' },
]

export default function PreferencesPage() {
  const { t } = useTranslation()
  const { theme, setTheme } = useTheme()
  const { preferences, isLoading, mutate } = usePreferences()
  const { updatePreferences, isUpdating } = useUpdatePreferences()

  // Form state
  const [formData, setFormData] = useState<UpdatePreferencesInput>({
    theme: 'system',
    language: 'en',
    findings_informational: 'default',
  })
  const [hasChanges, setHasChanges] = useState(false)

  // Populate form when preferences load. A personal time zone and date or
  // time format come back when one date formatter honours them (research
  // 273 D9); until then the browser's own zone and locale apply.
  useEffect(() => {
    if (preferences) {
      setFormData({
        theme: preferences.theme || 'system',
        language: preferences.language || 'en',
        findings_informational: preferences.findings_informational || 'default',
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

  // Save preferences (theme, language and the findings default are stored
  // on the server).
  const handleSave = async () => {
    try {
      await updatePreferences({
        theme: formData.theme,
        language: formData.language,
        findings_informational: formData.findings_informational,
      })
      // The findings work views follow the new choice.
      void refreshFindingQuickViews()
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
      findings_informational: 'default',
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

      {/* Findings */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bug className="h-5 w-5" />
            {t('account.preferences.findings', 'Findings')}
          </CardTitle>
          <CardDescription>
            {t(
              'account.preferences.findingsDescription',
              'How your findings work views (Active, My queue, SLA breached) open'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 sm:max-w-sm">
            <Label htmlFor="findings-informational">
              {t('account.preferences.findingsInformational', 'Informational findings')}
            </Label>
            <Select
              value={formData.findings_informational}
              onValueChange={(value) =>
                handleChange('findings_informational', value as FindingsInformationalPreference)
              }
            >
              <SelectTrigger id="findings-informational">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {INFORMATIONAL_CHOICES.map((c) => (
                  <SelectItem key={c.value} value={c.value}>
                    {t(`account.preferences.findingsInformational.${c.value}`, c.fallback)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              {t(
                'account.preferences.findingsInformationalHint',
                'Needs triage never lists them. All findings and an Informational severity filter always do.'
              )}
            </p>
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
