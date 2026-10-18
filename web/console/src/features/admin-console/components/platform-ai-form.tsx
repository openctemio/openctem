'use client'

import { useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { savePlatformAI, testPlatformAI } from '../api/use-platform-settings'
import type { PlatformAISettings } from '../types'
import {
  LockedByEnvironment,
  ReasonConfirmDialog,
  SecretField,
  SettingChangedLine,
  handleSaveConflict,
  secretPatch,
} from './console-setting-parts'

/** Provider names are product names; the catalog keeps them as they are. */
const PROVIDER_LABEL: Record<string, [key: string, fallback: string]> = {
  claude: ['admin.ai.providerName.claude', 'Anthropic Claude'],
  openai: ['admin.ai.providerName.openai', 'OpenAI'],
  gemini: ['admin.ai.providerName.gemini', 'Google Gemini'],
}

export interface PlatformAIFormProps {
  settings: PlatformAISettings
  canEdit: boolean
  onSaved: () => void
}

/**
 * Settings > AI provider: the provider, model and key organizations in
 * "platform" AI mode use. Off by default; organizations can always bring
 * their own key. The key is write-only.
 */
export function PlatformAIForm({ settings, canEdit, onSaved }: PlatformAIFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const locked = settings.locked_by_environment
  const editable = canEdit && !locked
  const [enabled, setEnabled] = useState(settings.enabled)
  const [provider, setProvider] = useState(settings.provider || settings.providers[0] || '')
  const [model, setModel] = useState(settings.model)
  const [key, setKey] = useState('')
  const [clearKey, setClearKey] = useState(false)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [testing, setTesting] = useState(false)

  useEffect(() => {
    setEnabled(settings.enabled)
    setProvider(settings.provider || settings.providers[0] || '')
    setModel(settings.model)
    setKey('')
    setClearKey(false)
  }, [settings])

  const providerChanged = settings.provider !== '' && provider !== settings.provider
  const willHaveKey = (settings.key_set && !clearKey && !providerChanged) || key.trim() !== ''
  const dirty =
    enabled !== settings.enabled ||
    provider !== settings.provider ||
    model.trim() !== settings.model ||
    key !== '' ||
    clearKey
  const incomplete = enabled && (!provider || model.trim() === '' || !willHaveKey)

  const test = async () => {
    setTesting(true)
    try {
      await testPlatformAI()
      toast.success(t('admin.ai.testOk', 'The provider accepted the key'))
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('admin.ai.testFailed', 'The key test failed'))
    } finally {
      setTesting(false)
    }
  }

  const save = async (reason: string) => {
    try {
      await savePlatformAI({
        enabled,
        provider,
        model: model.trim(),
        api_key: secretPatch(key, clearKey),
        reason,
        version: settings.version,
      })
      toast.success(t('admin.ai.saved', 'AI provider saved'))
      onSaved()
    } catch (e) {
      if (
        handleSaveConflict(
          e,
          onSaved,
          t(
            'admin.settings.conflict',
            'Another administrator changed this setting. The latest values are shown.'
          )
        )
      )
        return
      throw e
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>{t('admin.ai.title', 'Platform AI provider')}</CardTitle>
          <CardDescription>
            {t(
              'admin.ai.description',
              'Organizations in platform AI mode send findings for AI triage to this provider with this key. It is a cost and a processor of their data, so it is off until you turn it on. Organizations can always use their own key instead.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {locked && (
            <LockedByEnvironment envVar="ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY" />
          )}
          <div className="flex items-start justify-between gap-4 rounded-lg border p-4">
            <Label htmlFor={`${id}-enabled`} className="grid gap-1 font-normal">
              <span className="font-medium">{t('admin.ai.enabled', 'Offer platform AI')}</span>
              <span className="text-sm text-muted-foreground">
                {t(
                  'admin.ai.enabledHelp',
                  'Off: organizations in platform mode cannot run AI triage.'
                )}
              </span>
            </Label>
            <Switch
              id={`${id}-enabled`}
              checked={enabled}
              onCheckedChange={setEnabled}
              disabled={!editable}
            />
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label htmlFor={`${id}-provider`}>{t('admin.ai.provider', 'Provider')}</Label>
              <Select value={provider} onValueChange={setProvider} disabled={!editable}>
                <SelectTrigger id={`${id}-provider`}>
                  <SelectValue placeholder={t('admin.ai.providerPick', 'Choose a provider')} />
                </SelectTrigger>
                <SelectContent>
                  {settings.providers.map((p) => (
                    <SelectItem key={p} value={p}>
                      {PROVIDER_LABEL[p] ? t(...PROVIDER_LABEL[p]) : p}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor={`${id}-model`}>{t('admin.ai.model', 'Model')}</Label>
              <Input
                id={`${id}-model`}
                value={model}
                onChange={(e) => setModel(e.target.value)}
                disabled={!editable}
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            <SecretField
              label={t('admin.ai.key', 'API key')}
              isSet={settings.key_set && !providerChanged}
              value={key}
              onChange={setKey}
              clear={clearKey}
              onClear={setClearKey}
              disabled={!editable}
              help={
                providerChanged
                  ? t(
                      'admin.ai.keyNewProvider',
                      "A key belongs to one provider: enter the new provider's key."
                    )
                  : t(
                      'admin.ai.keyHelp',
                      'Write-only: encrypted on the server and never shown again.'
                    )
              }
            />
          </div>
          {incomplete && (
            <p className="text-sm text-destructive">
              {t(
                'admin.ai.incomplete',
                'Choose a provider and a model and set its key to turn platform AI on.'
              )}
            </p>
          )}
          <SettingChangedLine change={settings} />
          {canEdit && !locked && (
            <div className="flex flex-wrap items-center justify-end gap-3">
              <Button
                variant="outline"
                onClick={() => void test()}
                disabled={testing || dirty || !settings.key_set}
              >
                {testing && <Loader2 className="me-1.5 size-4 animate-spin" />}
                {t('admin.ai.test', 'Test the key')}
              </Button>
              <Button onClick={() => setConfirmOpen(true)} disabled={!dirty || incomplete}>
                {t('admin.settings.save', 'Save')}
              </Button>
            </div>
          )}
          {!canEdit && (
            <p className="text-sm text-muted-foreground">
              {t('admin.settings.superAdminOnly', 'Only a super admin can change this setting.')}
            </p>
          )}
        </CardContent>
      </Card>
      <ReasonConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title={t('admin.ai.confirmTitle', 'Change the platform AI provider?')}
        desc={t(
          'admin.ai.confirmDesc',
          'Applies at once to every organization in platform AI mode. Recorded in the admin audit log (never the key) and sent to every administrator.'
        )}
        onConfirm={save}
      />
    </>
  )
}
