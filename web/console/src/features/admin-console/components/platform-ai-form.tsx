'use client'

import { useCallback, useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import {
  SettingsBlock,
  SettingsField,
  SettingsFieldGrid,
  SettingsRow,
  SettingsSaveBar,
  SettingsSection,
  SettingsSwitchRow,
} from '@/features/shared'
import { saveOrgAIPolicy, savePlatformAI, testPlatformAI } from '../api/use-platform-settings'
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
  const [allowOrg, setAllowOrg] = useState(settings.allow_org_provider)
  const [policyConfirmOpen, setPolicyConfirmOpen] = useState(false)
  const [testing, setTesting] = useState(false)

  // The provider the form starts from: the saved one, or the first offered
  // when none is saved yet. Compared against it, a fresh form is not dirty.
  const initialProvider = settings.provider || settings.providers[0] || ''

  // The saved values: on load, after a save and on Discard.
  const reset = useCallback(() => {
    setEnabled(settings.enabled)
    setProvider(settings.provider || settings.providers[0] || '')
    setModel(settings.model)
    setBaseUrl(settings.base_url)
    setAllowPrivate(settings.allow_private)
    setAllowedModels(settings.allowed_models.join(', '))
    setAllowOrg(settings.allow_org_provider)
    setKey('')
    setClearKey(false)
  }, [settings])
  useEffect(reset, [reset])

  const providerChanged = settings.provider !== '' && provider !== settings.provider
  const compat = provider === 'openai_compatible'
  const willHaveKey = (settings.key_set && !clearKey && !providerChanged) || key.trim() !== ''
  const models = allowedModels
    .split(',')
    .map((m) => m.trim())
    .filter(Boolean)
  const dirty =
    enabled !== settings.enabled ||
    provider !== initialProvider ||
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

  const savePolicy = async (reason: string) => {
    try {
      await saveOrgAIPolicy({
        allow_org_provider: allowOrg,
        reason,
        version: settings.org_policy_version,
      })
      toast.success(t('admin.ai.policySaved', 'Policy saved'))
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
      <SettingsSection
        framed
        id="platform-ai"
        title={t('admin.ai.title', 'Platform AI provider')}
        description={t(
          'admin.ai.description',
          'Organizations in platform AI mode send findings for AI triage to this provider with this key. It is a cost and a processor of their data, so it is off until you turn it on. Organizations can always use their own key instead.'
        )}
        meta={<SettingChangedLine change={settings} />}
      >
        {locked && (
          <SettingsBlock>
            <LockedByEnvironment envVar="ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY" />
          </SettingsBlock>
        )}
        <SettingsSwitchRow
          id={`${id}-enabled`}
          label={t('admin.ai.enabled', 'Offer platform AI')}
          hint={t(
            'admin.ai.enabledHelp',
            'Off: organizations in platform mode cannot run AI triage.'
          )}
          checked={enabled}
          onCheckedChange={setEnabled}
          disabled={!editable}
        />
        <SettingsBlock>
          <SettingsFieldGrid>
            <SettingsField id={`${id}-provider`} label={t('admin.ai.provider', 'Provider')}>
              {(control) => (
                <Select value={provider} onValueChange={setProvider} disabled={!editable}>
                  <SelectTrigger {...control}>
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
              )}
            </SettingsField>
            <SettingsField id={`${id}-model`} label={t('admin.ai.model', 'Model')}>
              {(control) => (
                <Input
                  {...control}
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  disabled={!editable}
                  autoComplete="off"
                  spellCheck={false}
                />
              )}
            </SettingsField>
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
              <SettingsField
                id={`${id}-base-url`}
                label={t('admin.ai.baseUrl', 'Base URL')}
                hint={t(
                  'admin.ai.baseUrlHelp',
                  "The server's API root, for example https://llm.example.com/v1. Works with Azure OpenAI, vLLM, Ollama, LiteLLM, OpenRouter and gateways."
                )}
              >
                {(control) => (
                  <Input
                    {...control}
                    type="url"
                    value={baseUrl}
                    onChange={(e) => setBaseUrl(e.target.value)}
                    disabled={!editable}
                    autoComplete="off"
                    spellCheck={false}
                  />
                )}
              </SettingsField>
            )}
            <SettingsField
              id={`${id}-allowed-models`}
              label={t('admin.ai.allowedModels', 'Allowed models')}
              hint={t(
                'admin.ai.allowedModelsHelp',
                'Comma-separated. When set, the model above must be one of them. Leave empty to allow any.'
              )}
            >
              {(control) => (
                <Input
                  {...control}
                  value={allowedModels}
                  onChange={(e) => setAllowedModels(e.target.value)}
                  disabled={!editable}
                  autoComplete="off"
                  spellCheck={false}
                />
              )}
            </SettingsField>
          </SettingsFieldGrid>
          {incomplete && (
            <p className="text-dense text-destructive" role="alert">
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
        </SettingsBlock>
        {compat && (
          <SettingsSwitchRow
            id={`${id}-allow-private`}
            label={t('admin.ai.allowPrivate', 'Allow private addresses')}
            hint={t(
              'admin.ai.allowPrivateHelp',
              "Lets the base URL be on a private network (10.x, 172.16-31.x, 192.168.x) and use http, for a self-hosted model. Loopback, link-local and cloud-metadata addresses stay blocked. Organizations' own providers never get this."
            )}
            checked={allowPrivate}
            onCheckedChange={setAllowPrivate}
            disabled={!editable}
          />
        )}
        {/* Shown only when there is a saved key to test and nothing unsaved. */}
        {canEdit &&
          !locked &&
          !dirty &&
          (settings.key_set || settings.provider === 'openai_compatible') && (
            <SettingsRow
              label={t('admin.ai.test', 'Test the key')}
              hint={t(
                'admin.ai.testHint',
                'Asks the provider whether it accepts the saved key. Save your changes first.'
              )}
            >
              <Button variant="outline" onClick={() => void test()} disabled={testing}>
                {testing && <Loader2 className="animate-spin" aria-hidden />}
                {t('admin.ai.testButton', 'Test')}
              </Button>
            </SettingsRow>
          )}
      </SettingsSection>
      {canEdit && !locked && (
        <SettingsSaveBar
          dirty={dirty}
          saveDisabled={incomplete}
          onSave={() => setConfirmOpen(true)}
          onDiscard={reset}
        />
      )}
      <SettingsSection
        framed
        id="org-ai-providers"
        title={t('admin.ai.policyTitle', "Organizations' own AI providers")}
        description={t(
          'admin.ai.policyDescription',
          'Let organizations send their findings to their own AI provider with their own key (Settings > AI > Own provider). Their addresses must be public https; the private-address toggle above never applies to them.'
        )}
      >
        <SettingsSwitchRow
          id={`${id}-allow-org`}
          label={t('admin.ai.policyAllow', 'Allow organizations to use their own provider')}
          hint={t(
            'admin.ai.policyAllowHelp',
            'Off: every organization on its own provider stops at its next call. It never falls back to the platform key.'
          )}
          checked={allowOrg}
          onCheckedChange={setAllowOrg}
          disabled={!canEdit}
        />
        {canEdit && allowOrg !== settings.allow_org_provider && (
          <SettingsBlock className="flex-row justify-end">
            <Button variant="ghost" onClick={() => setAllowOrg(settings.allow_org_provider)}>
              {t('settings.saveBar.discard', 'Discard')}
            </Button>
            <Button onClick={() => setPolicyConfirmOpen(true)}>
              {t('admin.ai.policySave', 'Save policy')}
            </Button>
          </SettingsBlock>
        )}
      </SettingsSection>
      <ReasonConfirmDialog
        open={policyConfirmOpen}
        onOpenChange={setPolicyConfirmOpen}
        title={t(
          'admin.ai.policyConfirmTitle',
          "Change the policy on organizations' own providers?"
        )}
        desc={t(
          'admin.ai.policyConfirmDesc',
          'Applies at once to every organization. Recorded in the admin audit log and sent to every administrator.'
        )}
        confirmText={t('admin.ai.policyConfirmButton', 'Change policy')}
        onConfirm={savePolicy}
      />
      <ReasonConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title={t('admin.ai.confirmTitle', 'Change the platform AI provider?')}
        desc={t(
          'admin.ai.confirmDesc',
          'Applies at once to every organization in platform AI mode. Recorded in the admin audit log (never the key) and sent to every administrator.'
        )}
        confirmText={t('admin.ai.confirmButton', 'Change AI provider')}
        onConfirm={save}
      />
    </>
  )
}
