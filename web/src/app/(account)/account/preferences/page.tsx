'use client'

import { useEffect, useMemo, useState } from 'react'
import { useTheme } from 'next-themes'
import { toast } from 'sonner'

import { useTranslation } from '@/context/i18n-provider'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { LOCALE_LABELS, selectLocale } from '@/components/language-switcher'
import { getErrorMessage } from '@/lib/api/error-handler'
import { supportedLocales } from '@/lib/i18n'
import { usePreferences, useUpdatePreferences } from '@/features/account'
import type { FindingsInformationalPreference, UpdatePreferencesInput } from '@/features/account'
import { SettingsRow, SettingsSaveBar, SettingsSection } from '@/features/shared'

type Theme = 'light' | 'dark' | 'system'
type PreferencesForm = Required<
  Pick<UpdatePreferencesInput, 'theme' | 'language' | 'findings_informational'>
>

const THEMES: ReadonlyArray<{ value: Theme; fallback: string }> = [
  { value: 'light', fallback: 'Light' },
  { value: 'dark', fallback: 'Dark' },
  { value: 'system', fallback: 'System' },
]

const INFORMATIONAL_CHOICES: ReadonlyArray<{
  value: FindingsInformationalPreference
  fallback: string
}> = [
  { value: 'default', fallback: "Organization's default" },
  { value: 'exclude', fallback: 'Hide informational findings' },
  { value: 'include', fallback: 'Show informational findings' },
]

/**
 * Account > Preferences: theme, language and how findings views open. A new
 * theme shows at once (Discard puts the saved one back); every change is kept
 * through the save bar, shown only while there are unsaved changes. Saving a
 * new language reloads the page in it.
 */
export default function PreferencesPage() {
  const { t, locale } = useTranslation()
  const { setTheme } = useTheme()
  const { preferences, isLoading, mutate } = usePreferences()
  const { updatePreferences, isUpdating } = useUpdatePreferences()

  // A personal time zone and date or time format come back when one date
  // formatter honours them (research 273 D9); until then the browser's own
  // zone and locale apply.
  const saved = useMemo<PreferencesForm>(
    () => ({
      theme: preferences?.theme || 'system',
      language: preferences?.language || locale,
      findings_informational: preferences?.findings_informational || 'default',
    }),
    [preferences?.theme, preferences?.language, preferences?.findings_informational, locale]
  )
  const [form, setForm] = useState<PreferencesForm>(saved)
  const [saveError, setSaveError] = useState<string | null>(null)

  useEffect(() => {
    setForm(saved)
  }, [saved])

  const changes = [
    form.theme !== saved.theme && t('account.preferences.theme', 'Theme'),
    form.language !== saved.language && t('common.language', 'Language'),
    form.findings_informational !== saved.findings_informational &&
      t('account.preferences.findingsInformational', 'Informational findings'),
  ].filter((c): c is string => !!c)

  const change = <K extends keyof PreferencesForm>(field: K, value: PreferencesForm[K]) => {
    setForm((prev) => ({ ...prev, [field]: value }))
    // The theme shows at once, so the choice can be judged before saving.
    if (field === 'theme') setTheme(value as Theme)
  }

  const handleSave = async () => {
    setSaveError(null)
    try {
      await updatePreferences(form)
      // Re-read the preferences from the server rather than caching the PUT
      // response: an older API returned the whole user object there, which
      // reset this form to its defaults (23a B4).
      await mutate()
      if (form.language !== locale) {
        // The page is drawn again in the new language.
        selectLocale(form.language)
        return
      }
      toast.success(t('account.preferences.saved', 'Preferences saved'))
    } catch (error) {
      setSaveError(
        getErrorMessage(error, t('account.preferences.saveFailed', 'Could not save preferences'))
      )
    }
  }

  const discard = () => {
    setForm(saved)
    setTheme(saved.theme)
    setSaveError(null)
  }

  if (isLoading) {
    return (
      <div aria-busy="true" className="flex flex-col">
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            className="flex items-center justify-between gap-8 border-t border-border-subtle py-3.5 first:border-t-0"
          >
            <div className="min-w-0 flex-1 space-y-2">
              <Skeleton className="h-4 w-48 max-w-full" />
              <Skeleton className="h-3 w-80 max-w-full" />
            </div>
            <Skeleton className="h-8 w-32" />
          </div>
        ))}
      </div>
    )
  }

  return (
    <>
      <SettingsSection
        framed
        id="appearance"
        title={t('account.preferences.appearance', 'Appearance')}
      >
        <SettingsRow
          wide
          labelId="theme-label"
          label={t('account.preferences.theme', 'Theme')}
          hint={t(
            'account.preferences.theme.systemHint',
            'System follows the light or dark setting of your device.'
          )}
        >
          <Select value={form.theme} onValueChange={(v) => change('theme', v as Theme)}>
            <SelectTrigger aria-labelledby="theme-label" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {THEMES.map((mode) => (
                <SelectItem key={mode.value} value={mode.value}>
                  {t(`account.preferences.theme.${mode.value}`, mode.fallback)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </SettingsRow>
        <SettingsRow
          wide
          labelId="language-label"
          label={t('common.language', 'Language')}
          hint={t(
            'account.preferences.languageHint',
            'The page opens again in the new language when you save.'
          )}
        >
          <Select value={form.language} onValueChange={(v) => change('language', v)}>
            <SelectTrigger aria-labelledby="language-label" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {supportedLocales.map((l) => (
                <SelectItem key={l} value={l}>
                  {LOCALE_LABELS[l] ?? l}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </SettingsRow>
      </SettingsSection>

      {/* Findings: the default every organization's findings views open with. */}
      <SettingsSection
        framed
        id="findings"
        title={t('account.preferences.findings', 'Findings')}
        description={t(
          'account.preferences.findingsDescription',
          'How your findings work views (Active, My queue, SLA breached) open'
        )}
      >
        <SettingsRow
          wide
          labelId="findings-informational-label"
          label={t('account.preferences.findingsInformational', 'Informational findings')}
          hint={t(
            'account.preferences.findingsInformationalHint',
            'Needs triage never lists them. All findings and an Informational severity filter always do.'
          )}
        >
          <Select
            value={form.findings_informational}
            onValueChange={(value) =>
              change('findings_informational', value as FindingsInformationalPreference)
            }
          >
            <SelectTrigger
              id="findings-informational"
              aria-labelledby="findings-informational-label"
              className="w-full"
            >
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
        </SettingsRow>
      </SettingsSection>

      <SettingsSaveBar
        dirty={changes.length > 0}
        saving={isUpdating}
        onSave={handleSave}
        onDiscard={discard}
        changes={changes}
        error={saveError}
      />
    </>
  )
}
