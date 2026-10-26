'use client'

import { useEffect, useId, useState } from 'react'
import { KeyRound, Loader2, ShieldAlert } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe } from '@/lib/format-date'

import {
  testAIProvider,
  updateAISettings,
  type AIProviderKind,
  type AISettings,
  type AISettingsPatch,
  type AISource,
  type AITestCode,
} from '../api/use-ai-settings'

/** Provider names are product names; the catalog keeps them as they are. */
const PROVIDER_LABEL: Record<AIProviderKind, [key: string, fallback: string]> = {
  claude: ['settings.ai.source.providerName.claude', 'Anthropic Claude'],
  openai: ['settings.ai.source.providerName.openai', 'OpenAI'],
  gemini: ['settings.ai.source.providerName.gemini', 'Google Gemini'],
  openai_compatible: [
    'settings.ai.source.providerName.openai_compatible',
    'OpenAI-compatible server',
  ],
}

const TEST_MESSAGE: Record<AITestCode, string> = {
  ok: 'Connected: the provider answered.',
  invalid_url: 'The base URL is not valid. Use a full https address.',
  blocked_address:
    'This address is not allowed: it must be a public https address (not a private, loopback or link-local one).',
  key_required: 'Enter the API key to test with.',
  not_configured: 'Choose a provider and a model first.',
  auth_failed: 'The provider refused the key.',
  rate_limited: 'The provider is rate limiting this key. Try again in a moment.',
  timeout: 'The provider did not answer in time.',
  unreachable: 'The provider could not be reached.',
  provider_error: 'The provider answered with an error. Check the model name.',
}

export interface AISourceCardProps {
  settings: AISettings
  canEdit: boolean
  /** Called with the saved settings. */
  onSaved: (next: AISettings) => void
}

/**
 * Settings > AI > Source: where the AI comes from (the platform's provider,
 * the organization's own provider, or off). The own provider's key is
 * write-only: it is shown only as set, its last four characters and when it
 * was set. A save needs a recent sign-in (the shared client asks for it) and
 * is audited; the server never sends the key back.
 */
export function AISourceCard({ settings, canEdit, onSaved }: AISourceCardProps) {
  const { t } = useTranslation()
  const id = useId()
  const [source, setSource] = useState<AISource>(settings.source)
  const [provider, setProvider] = useState<AIProviderKind | ''>(settings.provider)
  const [baseUrl, setBaseUrl] = useState(settings.base_url)
  const [model, setModel] = useState(settings.model)
  const [key, setKey] = useState('')
  const [removeKey, setRemoveKey] = useState(false)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testCode, setTestCode] = useState<AITestCode | undefined>()

  useEffect(() => {
    setSource(settings.source)
    setProvider(settings.provider)
    setBaseUrl(settings.base_url)
    setModel(settings.model)
    setKey('')
    setRemoveKey(false)
    setTestCode(undefined)
  }, [settings])

  const own = source === 'own'
  const compat = provider === 'openai_compatible'
  const targetChanged =
    provider !== settings.provider || (compat && baseUrl.trim() !== settings.base_url)
  // A stored key belongs to one endpoint: a new provider or base URL needs a new key.
  const keySet = settings.key.set && !removeKey && !targetChanged
  const hasKey = keySet || key.trim() !== ''
  const dirty =
    source !== settings.source ||
    (own &&
      (provider !== settings.provider ||
        model.trim() !== settings.model ||
        baseUrl.trim() !== settings.base_url ||
        key !== '' ||
        removeKey))
  const incomplete =
    own && (provider === '' || (compat ? baseUrl.trim() === '' || model.trim() === '' : !hasKey))

  const values = (): AISettingsPatch => {
    const v: AISettingsPatch = { source }
    if (!own) return v
    v.provider = provider
    v.base_url = compat ? baseUrl.trim() : ''
    v.model = model.trim()
    if (key.trim() !== '') v.api_key = key.trim()
    else if (removeKey) v.api_key = ''
    return v
  }

  const save = async () => {
    setSaving(true)
    try {
      const next = await updateAISettings(values())
      onSaved(next)
      toast.success(t('settings.ai.source.saved', 'AI source saved'))
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  const test = async () => {
    setTesting(true)
    setTestCode(undefined)
    try {
      const body: AISettingsPatch = {
        provider,
        base_url: compat ? baseUrl.trim() : '',
        model: model.trim(),
      }
      if (key.trim() !== '') body.api_key = key.trim()
      const res = await testAIProvider(body)
      setTestCode(res.code)
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setTesting(false)
    }
  }

  const sources: { value: AISource; title: string; desc: string; disabled?: boolean }[] = [
    {
      value: 'platform',
      title: t('settings.ai.source.platform', 'Platform AI'),
      desc: t(
        'settings.ai.source.platformDesc',
        'Use the AI provider your platform administrator set up. Counts toward your monthly allowance.'
      ),
    },
    {
      value: 'own',
      title: t('settings.ai.source.own', 'Own provider'),
      desc: settings.own_provider_allowed
        ? t(
            'settings.ai.source.ownDesc',
            'Use your own account with an AI provider or a server you run. Finding content goes to that provider; the platform never sees your key.'
          )
        : t(
            'settings.ai.source.ownNotAllowed',
            'Your platform administrator has turned off own providers for this installation.'
          ),
      disabled: !settings.own_provider_allowed && settings.source !== 'own',
    },
    {
      value: 'off',
      title: t('settings.ai.source.off', 'Off'),
      desc: t(
        'settings.ai.source.offDesc',
        'Do not use AI triage, even when it is turned on above.'
      ),
    },
  ]

  const keyDate = formatDateSafe(settings.key.updated_at)
  const testMessage = testCode
    ? t(`settings.ai.source.test.${testCode}`, TEST_MESSAGE[testCode])
    : ''

  return (
    <Card id="ai-source">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="h-4 w-4" aria-hidden />
          {t('settings.ai.source.title', 'AI source')}
        </CardTitle>
        <CardDescription>
          {t(
            'settings.ai.source.description',
            'Choose which AI analyses your findings. Saving needs a recent sign-in and is recorded in the audit log.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        {!settings.own_provider_allowed && settings.source === 'own' && (
          <p className="flex items-start gap-2 text-sm text-destructive" role="alert">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
            {t(
              'settings.ai.source.ownBlocked',
              'The platform no longer allows own providers: AI triage is paused for your organization. Switch to Platform AI or Off.'
            )}
          </p>
        )}
        <RadioGroup
          value={source}
          onValueChange={(v) => setSource(v as AISource)}
          disabled={!canEdit || saving}
          aria-label={t('settings.ai.source.title', 'AI source')}
        >
          {sources.map((s) => (
            <div key={s.value} className="flex items-start gap-3">
              <RadioGroupItem
                id={`${id}-${s.value}`}
                value={s.value}
                disabled={s.disabled || !canEdit || saving}
                className="mt-1"
              />
              <Label htmlFor={`${id}-${s.value}`} className="grid gap-0.5 font-normal">
                <span className="font-medium">{s.title}</span>
                <span className="text-sm text-muted-foreground">{s.desc}</span>
              </Label>
            </div>
          ))}
        </RadioGroup>

        {own && (
          <div className="grid gap-4 rounded-md border p-4 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label htmlFor={`${id}-provider`}>
                {t('settings.ai.source.provider', 'Provider')}
              </Label>
              <Select
                value={provider}
                onValueChange={(v) => setProvider(v as AIProviderKind)}
                disabled={!canEdit || saving}
              >
                <SelectTrigger id={`${id}-provider`}>
                  <SelectValue
                    placeholder={t('settings.ai.source.providerPick', 'Choose a provider')}
                  />
                </SelectTrigger>
                <SelectContent>
                  {settings.providers.map((p) => (
                    <SelectItem key={p} value={p}>
                      {t(...PROVIDER_LABEL[p])}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor={`${id}-model`}>{t('settings.ai.source.model', 'Model')}</Label>
              <Input
                id={`${id}-model`}
                value={model}
                onChange={(e) => setModel(e.target.value)}
                disabled={!canEdit || saving}
                autoComplete="off"
                spellCheck={false}
                placeholder={
                  compat
                    ? t('settings.ai.source.modelRequired', 'Required, for example llama3')
                    : t('settings.ai.source.modelDefault', 'Leave empty for the default')
                }
              />
            </div>
            {compat && (
              <div className="grid gap-1.5 sm:col-span-2">
                <Label htmlFor={`${id}-base-url`}>
                  {t('settings.ai.source.baseUrl', 'Base URL')}
                </Label>
                <Input
                  id={`${id}-base-url`}
                  type="url"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  disabled={!canEdit || saving}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="https://llm.example.com/v1"
                  aria-describedby={`${id}-base-url-help`}
                />
                <p id={`${id}-base-url-help`} className="text-sm text-muted-foreground">
                  {t(
                    'settings.ai.source.baseUrlHelp',
                    'A public https address of a server that speaks the OpenAI chat API (Azure OpenAI, vLLM, Ollama, LiteLLM, OpenRouter, a gateway). Private network addresses are not allowed.'
                  )}
                </p>
              </div>
            )}
            <div className="grid gap-1.5 sm:col-span-2">
              <Label htmlFor={`${id}-key`}>{t('settings.ai.source.key', 'API key')}</Label>
              <Input
                id={`${id}-key`}
                type="password"
                value={key}
                onChange={(e) => setKey(e.target.value)}
                disabled={!canEdit || saving || removeKey}
                autoComplete="new-password"
                spellCheck={false}
                placeholder={
                  keySet
                    ? t('settings.ai.source.keyKeep', 'Leave empty to keep the saved key')
                    : compat
                      ? t('settings.ai.source.keyOptional', 'Optional for this provider')
                      : ''
                }
                aria-describedby={`${id}-key-help`}
              />
              <p id={`${id}-key-help`} className="text-sm text-muted-foreground">
                {settings.key.set && !targetChanged
                  ? t(
                      'settings.ai.source.keyStatus',
                      'A key is set (ends in {last4}), updated {date}. It is never shown again.',
                      { last4: settings.key.last4 || '••••', date: keyDate }
                    )
                  : settings.key.set
                    ? t(
                        'settings.ai.source.keyNewTarget',
                        'The saved key belongs to the previous provider or address, so it will be removed. Enter the key for this one.'
                      )
                    : t(
                        'settings.ai.source.keyHelp',
                        'Write-only: encrypted on the server and never shown again.'
                      )}
              </p>
              {settings.key.set && canEdit && !targetChanged && (
                <div className="flex items-center gap-2">
                  <input
                    id={`${id}-remove-key`}
                    type="checkbox"
                    checked={removeKey}
                    onChange={(e) => setRemoveKey(e.target.checked)}
                    disabled={saving}
                    className="h-4 w-4"
                  />
                  <Label htmlFor={`${id}-remove-key`} className="font-normal">
                    {t('settings.ai.source.keyRemove', 'Remove the saved key')}
                  </Label>
                </div>
              )}
            </div>
          </div>
        )}

        {own && incomplete && (
          <p className="text-sm text-destructive">
            {compat
              ? t(
                  'settings.ai.source.incompleteCompat',
                  'An OpenAI-compatible server needs a base URL and a model.'
                )
              : t(
                  'settings.ai.source.incomplete',
                  'Choose a provider and enter its API key to use your own.'
                )}
          </p>
        )}

        <div aria-live="polite" className="min-h-5 text-sm">
          {testCode && (
            <p className={testCode === 'ok' ? 'text-success' : 'text-destructive'}>{testMessage}</p>
          )}
        </div>

        {canEdit && (
          <div className="flex flex-wrap items-center justify-end gap-3">
            {own && (
              <Button
                type="button"
                variant="outline"
                onClick={() => void test()}
                disabled={testing || saving || provider === '' || (!compat && !hasKey)}
              >
                {testing && <Loader2 className="me-1.5 size-4 animate-spin" aria-hidden />}
                {t('settings.ai.source.test', 'Test connection')}
              </Button>
            )}
            <Button
              type="button"
              onClick={() => void save()}
              disabled={!dirty || incomplete || saving}
            >
              {saving && <Loader2 className="me-1.5 size-4 animate-spin" aria-hidden />}
              {t('settings.ai.source.save', 'Save')}
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
