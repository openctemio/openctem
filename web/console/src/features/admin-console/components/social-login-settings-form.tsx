'use client'

import { useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { TonePill } from '@/features/shared/components/tone-pill'
import { saveSocialProvider, testSocialProvider } from '../api/use-platform-settings'
import type { SocialLoginSettings, SocialProvider } from '../types'
import {
  LockedByEnvironment,
  ReasonConfirmDialog,
  SecretField,
  SettingChangedLine,
  handleSaveConflict,
  secretPatch,
} from './console-setting-parts'

const NAMES: Record<SocialProvider['provider'], string> = {
  google: 'Google',
  github: 'GitHub',
  microsoft: 'Microsoft',
}

/** A read-only value to paste into the provider's console, with a copy button. */
function CopyField({ label, value }: { label: string; value: string }) {
  const { t } = useTranslation()
  const id = useId()
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      <div className="flex gap-2">
        <Input id={id} value={value} readOnly className="font-mono text-xs" />
        <Button
          type="button"
          variant="outline"
          onClick={() => {
            void navigator.clipboard?.writeText(value)
            toast.success(t('admin.socialLogin.copied', 'Copied'))
          }}
        >
          {t('admin.socialLogin.copy', 'Copy')}
        </Button>
      </div>
    </div>
  )
}

/** Who a social sign-in admits, in words, for the current sign-up policy. */
export function signupImpactKey(accounts: SocialLoginSettings['signup_accounts']) {
  return `admin.socialLogin.impact.${accounts}`
}

interface CardProps {
  settings: SocialLoginSettings
  provider: SocialProvider
  canEdit: boolean
  onSaved: () => void
}

function ProviderCard({ settings, provider: p, canEdit, onSaved }: CardProps) {
  const { t } = useTranslation()
  const id = useId()
  const name = NAMES[p.provider]
  const locked = p.locked_by_environment
  const editable = canEdit && !locked
  const [enabled, setEnabled] = useState(p.enabled)
  const [clientId, setClientId] = useState(p.client_id)
  const [secret, setSecret] = useState('')
  const [clearSecret, setClearSecret] = useState(false)
  const [scopes, setScopes] = useState(p.scopes.join(' '))
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [checking, setChecking] = useState(false)

  useEffect(() => {
    setEnabled(p.enabled)
    setClientId(p.client_id)
    setSecret('')
    setClearSecret(false)
    setScopes(p.scopes.join(' '))
  }, [p])

  const scopeList = scopes.split(/\s+/).filter(Boolean)
  const dirty =
    enabled !== p.enabled ||
    clientId.trim() !== p.client_id ||
    secret !== '' ||
    clearSecret ||
    scopeList.join(' ') !== p.scopes.join(' ')
  const turningOn = enabled && !p.enabled

  const pill = locked
    ? {
        tone: 'muted' as const,
        label: t('admin.socialLogin.statusEnv', 'Set by the server environment'),
      }
    : p.undecryptable
      ? {
          tone: 'warning' as const,
          label: t('admin.socialLogin.statusUndecryptable', 'Secret must be replaced'),
        }
      : !settings.master_enabled
        ? { tone: 'muted' as const, label: t('admin.socialLogin.statusMaster', 'Switched off') }
        : p.active
          ? { tone: 'success' as const, label: t('admin.socialLogin.statusOn', 'Offered') }
          : p.secret_set
            ? {
                tone: 'muted' as const,
                label: t('admin.socialLogin.statusReady', 'Ready, not offered'),
              }
            : { tone: 'muted' as const, label: t('admin.socialLogin.statusOff', 'Not set up') }

  const check = async () => {
    setChecking(true)
    try {
      const { result } = await testSocialProvider(p.provider, {
        client_id: clientId.trim() || undefined,
        secret: secret.trim() || undefined,
      })
      const msg: Record<string, [string, string]> = {
        valid: ['admin.socialLogin.checkValid', '{name} accepts this client'],
        invalid: [
          'admin.socialLogin.checkInvalid',
          '{name} does not accept this client ID and secret',
        ],
        redirect_mismatch: [
          'admin.socialLogin.checkRedirect',
          '{name} knows the client, but the redirect URI above is not registered for it',
        ],
        unreachable: [
          'admin.socialLogin.checkUnreachable',
          '{name} could not be reached; nothing is known about the client',
        ],
        unknown: ['admin.socialLogin.checkUnknown', '{name} gave an answer this check cannot read'],
      }
      const [key, fallback] = msg[result] ?? msg.unknown
      const text = t(key, fallback, { name })
      if (result === 'valid') toast.success(text)
      else if (result === 'invalid' || result === 'redirect_mismatch') toast.error(text)
      else toast.warning(text)
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : t('admin.socialLogin.checkFailed', 'The check failed')
      )
    } finally {
      setChecking(false)
    }
  }

  const save = async (reason: string) => {
    try {
      await saveSocialProvider(p.provider, {
        enabled,
        client_id: clientId.trim(),
        secret: secretPatch(secret, clearSecret),
        scopes: scopeList,
        reason,
        version: settings.version,
      })
      toast.success(t('admin.socialLogin.saved', '{name} sign-in saved', { name }))
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

  const impact = t(signupImpactKey(settings.signup_accounts))

  return (
    <>
      <Card data-testid={`social-${p.provider}`}>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <CardTitle>{name}</CardTitle>
            <TonePill tone={pill.tone} label={pill.label} />
          </div>
          <CardDescription>{t(`admin.socialLogin.note.${p.provider}`)}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {locked && <LockedByEnvironment envVar={p.env_var} />}
          <div className="grid gap-4 sm:grid-cols-2">
            <CopyField
              label={t('admin.socialLogin.redirectUri', 'Redirect URI to register')}
              value={p.redirect_uri}
            />
            {p.provider === 'google' && (
              <CopyField
                label={t('admin.socialLogin.jsOrigin', 'Authorized JavaScript origin')}
                value={settings.javascript_origin}
              />
            )}
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label htmlFor={`${id}-client`}>{t('admin.socialLogin.clientId', 'Client ID')}</Label>
              <Input
                id={`${id}-client`}
                value={clientId}
                onChange={(e) => setClientId(e.target.value)}
                disabled={!editable}
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            <SecretField
              label={t('admin.socialLogin.clientSecret', 'Client secret')}
              isSet={p.secret_set}
              value={secret}
              onChange={setSecret}
              clear={clearSecret}
              onClear={setClearSecret}
              disabled={!editable}
              help={t(
                'admin.socialLogin.secretHelp',
                'Write-only: it is encrypted on the server and never shown again.'
              )}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor={`${id}-scopes`}>{t('admin.socialLogin.scopes', 'Scopes')}</Label>
            <Input
              id={`${id}-scopes`}
              value={scopes}
              onChange={(e) => setScopes(e.target.value)}
              disabled={!editable}
              autoComplete="off"
              spellCheck={false}
              placeholder={p.default_scopes.join(' ')}
            />
            <p className="text-xs text-muted-foreground">
              {t(
                'admin.socialLogin.scopesHelp',
                'Separated by spaces. Leave empty to use the defaults shown. The scopes that identify the person cannot be removed.'
              )}
            </p>
          </div>
          <div className="flex items-center gap-3">
            <Switch
              id={`${id}-enabled`}
              checked={enabled}
              onCheckedChange={setEnabled}
              disabled={!editable}
            />
            <Label htmlFor={`${id}-enabled`}>
              {t('admin.socialLogin.offer', 'Offer on the sign-in page')}
            </Label>
          </div>
          {enabled && (
            <Alert>
              <AlertDescription>{impact}</AlertDescription>
            </Alert>
          )}
          {!settings.master_enabled && (
            <p className="text-sm text-muted-foreground">
              {t(
                'admin.socialLogin.masterOff',
                'Social sign-in is switched off for the whole server (OAUTH_ENABLED). Nothing is offered until the server setting is changed.'
              )}
            </p>
          )}
          <SettingChangedLine change={settings} />
          {canEdit && (
            <div className="flex flex-wrap items-center justify-end gap-3">
              <Button
                variant="outline"
                onClick={() => void check()}
                disabled={
                  checking || (!p.secret_set && (clientId.trim() === '' || secret.trim() === ''))
                }
              >
                {checking && <Loader2 className="me-1.5 size-4 animate-spin" />}
                {t('admin.socialLogin.check', 'Test configuration')}
              </Button>
              {!locked && (
                <Button onClick={() => setConfirmOpen(true)} disabled={!dirty}>
                  {t('admin.settings.save', 'Save')}
                </Button>
              )}
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
        destructive={clearSecret}
        title={t('admin.socialLogin.confirmTitle', 'Change {name} sign-in?', { name })}
        desc={
          turningOn
            ? `${impact} ${t('admin.socialLogin.confirmDesc', 'Applies at once on every server. Recorded in the admin audit log (never the secret) and sent to every administrator.')}`
            : t(
                'admin.socialLogin.confirmDesc',
                'Applies at once on every server. Recorded in the admin audit log (never the secret) and sent to every administrator.'
              )
        }
        confirmText={t('admin.socialLogin.confirmButton', 'Change {name} sign-in', { name })}
        onConfirm={save}
      />
    </>
  )
}

export interface SocialLoginSettingsFormProps {
  settings: SocialLoginSettings
  canEdit: boolean
  onSaved: () => void
}

/**
 * Settings > Social login: Google, GitHub and Microsoft sign-in. One card per
 * provider with the exact redirect URI to register, the client, a write-only
 * secret and a configuration test. A change applies at once on every server,
 * needs a reason and is told to every administrator. A provider set by the
 * server environment is shown read-only.
 */
export function SocialLoginSettingsForm({
  settings,
  canEdit,
  onSaved,
}: SocialLoginSettingsFormProps) {
  return (
    <div className="space-y-6">
      {settings.providers.map((p) => (
        <ProviderCard
          key={p.provider}
          settings={settings}
          provider={p}
          canEdit={canEdit}
          onSaved={onSaved}
        />
      ))}
    </div>
  )
}
