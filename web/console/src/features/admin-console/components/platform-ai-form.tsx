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
  openai_compatible: ['admin.ai.providerName.openai_compatible', 'OpenAI-compatible server'],
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
  const [baseUrl, setBaseUrl] = useState(settings.base_url)
  const [allowPrivate, setAllowPrivate] = useState(settings.allow_private)
  const [allowedModels, setAllowedModels] = useState(settings.allowed_models.join(', '))
  const [key, setKey] = useState('')
  const [clearKey, setClearKey] = useState(false)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [testing, setTesting] = useState(false)

  useEffect(() => {
    setEnabled(settings.enabled)
    setProvider(settings.provider || settings.providers[0] || '')
    setModel(settings.model)
    setBaseUrl(settings.base_url)
    setAllowPrivate(settings.allow_private)
    setAllowedModels(settings.allowed_models.join(', '))
    setKey('')
    setClearKey(false)
  }, [settings])

  const providerChanged = settings.provider !== '' && provider !== settings.provider
  const compat = provider === 'openai_compatible'
  const willHaveKey = (settings.key_set && !clearKey && !providerChanged) || key.trim() !== ''
  const models = allowedModels
    .split(',')
    .map((m) => m.trim())
    .filter(Boolean)
  const dirty =
    enabled !== settings.enabled ||
    provider !== settings.provider ||
    model.trim() !== settings.model ||
    (compat && (baseUrl.trim() !== settings.base_url || allowPrivate !== settings.allow_private)) ||
    models.join(',') !== settings.allowed_models.join(',') ||
    key !== '' ||
    clearKey
  const incomplete =
    enabled && (!provider || model.trim() === '' || (compat ? baseUrl.trim() === '' : !willHaveKey))

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
        base_url: compat ? baseUrl.trim() : '',
        allow_private: compat && allowPrivate,
        allowed_models: models,
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
                compat
                  ? t(
                      'admin.ai.keyOptional',
                      'Optional for this provider: a server inside your network may not need a key.'
                    )
                  : providerChanged
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
            {compat && (
              <div className="grid gap-1.5 sm:col-span-2">
                <Label htmlFor={`${id}-base-url`}>{t('admin.ai.baseUrl', 'Base URL')}</Label>
                <Input
                  id={`${id}-base-url`}
                  type="url"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  disabled={!editable}
                  autoComplete="off"
                  spellCheck={false}
                  aria-describedby={`${id}-base-url-help`}
                />
                <p id={`${id}-base-url-help`} className="text-sm text-muted-foreground">
                  {t(
                    'admin.ai.baseUrlHelp',
                    "The server's API root, for example https://llm.example.com/v1. Works with Azure OpenAI, vLLM, Ollama, LiteLLM, OpenRouter and gateways."
                  )}
                </p>
              </div>
            )}
            <div className="grid gap-1.5 sm:col-span-2">
              <Label htmlFor={`${id}-allowed-models`}>
                {t('admin.ai.allowedModels', 'Allowed models')}
              </Label>
              <Input
                id={`${id}-allowed-models`}
                value={allowedModels}
                onChange={(e) => setAllowedModels(e.target.value)}
                disabled={!editable}
                autoComplete="off"
                spellCheck={false}
                aria-describedby={`${id}-allowed-models-help`}
              />
              <p id={`${id}-allowed-models-help`} className="text-sm text-muted-foreground">
                {t(
                  'admin.ai.allowedModelsHelp',
                  'Comma-separated. When set, the model above must be one of them. Leave empty to allow any.'
                )}
              </p>
            </div>
          </div>
          {compat && (
            <div className="flex items-start justify-between gap-4 rounded-lg border p-4">
              <Label htmlFor={`${id}-allow-private`} className="grid gap-1 font-normal">
                <span className="font-medium">
                  {t('admin.ai.allowPrivate', 'Allow private addresses')}
                </span>
                <span className="text-sm text-muted-foreground">
                  {t(
                    'admin.ai.allowPrivateHelp',
                    "Lets the base URL be on a private network (10.x, 172.16-31.x, 192.168.x) and use http, for a self-hosted model. Loopback, link-local and cloud-metadata addresses stay blocked. Organizations' own providers never get this."
                  )}
                </span>
              </Label>
              <Switch
                id={`${id}-allow-private`}
                checked={allowPrivate}
                onCheckedChange={setAllowPrivate}
                disabled={!editable}
              />
            </div>
          )}
          {incomplete && (
            <p className="text-sm text-destructive" role="alert">
              {compat
                ? t(
                    'admin.ai.incompleteCompat',
                    'Choose a model and a base URL to turn platform AI on with an OpenAI-compatible server.'
                  )
                : t(
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
                disabled={
                  testing ||
                  dirty ||
                  !(settings.key_set || settings.provider === 'openai_compatible')
                }
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
