'use client'

import { useBrand } from '@/context/brand-provider'
import { useCallback, useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
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
import type { EmailSettingsResponse } from '@/lib/api/generated'
import { AdminApiError } from '@console/lib/admin-api/client'
import { saveEmailSettings, sendTestEmail } from '../api/use-email-settings'
import { SecretField } from './console-setting-parts'
import { ReasonAndCodeFields, useReasonAndCode } from './step-up-code-hint'

export interface EmailSettingsFormProps {
  settings: EmailSettingsResponse
  /** False for an administrator who may read but not change the settings. */
  canEdit: boolean
  onSaved: () => void
}

interface FormState {
  enabled: boolean
  host: string
  port: string
  username: string
  from: string
  fromName: string
  starttls: boolean
}

function toForm(s: EmailSettingsResponse): FormState {
  return {
    enabled: !!s.enabled,
    host: s.host ?? '',
    port: s.port ? String(s.port) : '587',
    username: s.username ?? '',
    from: s.from ?? '',
    fromName: s.from_name ?? '',
    starttls: s.version ? !!s.starttls : true,
  }
}

/** Failure reasons the API names for a test e-mail; each has an admin.email.testFailed.<reason> text. */
const TEST_REASONS = [
  'unknown_authority',
  'hostname_mismatch',
  'certificate_invalid',
  'tls_failed',
  'auth_failed',
  'auth_required',
  'sender_rejected',
  'relay_denied',
  'host_rejected',
  'connect_failed',
  'timeout',
  'not_configured',
  'no_address',
  'unknown',
]

/**
 * System > E-mail: the platform's SMTP server, used for sign-up, invitations,
 * verification and password e-mails when an organization has no e-mail
 * integration of its own. The password is write-only: it is never shown, only
 * replaced or cleared. A save needs a fresh authenticator code.
 */
export function EmailSettingsForm({ settings, canEdit, onSaved }: EmailSettingsFormProps) {
  const brand = useBrand()
  const { t } = useTranslation()
  const id = useId()
  const [form, setForm] = useState<FormState>(() => toForm(settings))
  const [password, setPassword] = useState('')
  const [clearPassword, setClearPassword] = useState(false)
  const [caPem, setCaPem] = useState('')
  const [clearCa, setClearCa] = useState(false)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const rc = useReasonAndCode(confirmOpen)
  const [busy, setBusy] = useState(false)
  const [testing, setTesting] = useState(false)

  // The saved values: on load, after a save and on Discard.
  const reset = useCallback(() => {
    setForm(toForm(settings))
    setPassword('')
    setClearPassword(false)
    setCaPem('')
    setClearCa(false)
  }, [settings])
  useEffect(reset, [reset])

  const set = <K extends keyof FormState>(k: K, v: FormState[K]) =>
    setForm((f) => ({ ...f, [k]: v }))
  const original = toForm(settings)
  const dirty =
    password !== '' ||
    clearPassword ||
    caPem.trim() !== '' ||
    clearCa ||
    (Object.keys(form) as (keyof FormState)[]).some((k) => form[k] !== original[k])

  const save = async () => {
    setBusy(true)
    rc.setCodeError(null)
    try {
      await saveEmailSettings({
        enabled: form.enabled,
        host: form.host.trim(),
        port: Number(form.port),
        username: form.username.trim(),
        // Omitted: keep the stored password.
        ...(clearPassword ? { password: '' } : password !== '' ? { password } : {}),
        from: form.from.trim(),
        from_name: form.fromName.trim(),
        starttls: form.starttls,
        // Omitted: keep the stored CA bundle.
        ...(clearCa ? { ca_pem: '' } : caPem.trim() !== '' ? { ca_pem: caPem.trim() } : {}),
        version: settings.version ?? 0,
        totp_code: rc.code.trim(),
      })
      setConfirmOpen(false)
      toast.success(t('admin.email.saved', 'E-mail settings saved'))
      onSaved()
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        rc.refuseCode(e.message)
        return
      }
      setConfirmOpen(false)
      if (e instanceof AdminApiError && e.status === 409) {
        toast.error(
          t(
            'admin.email.conflict',
            'Another administrator changed the settings. The latest values are shown.'
          )
        )
        onSaved()
        return
      }
      toast.error(
        e instanceof Error
          ? e.message
          : t('admin.email.saveFailed', 'Could not save the e-mail settings')
      )
    } finally {
      setBusy(false)
    }
  }

  const test = async () => {
    setTesting(true)
    try {
      await sendTestEmail()
      toast.success(t('admin.email.testSent', 'Test e-mail sent to your address'))
    } catch (e) {
      const reason =
        e instanceof AdminApiError && e.details && typeof e.details === 'object'
          ? (e.details as { reason?: string }).reason
          : undefined
      toast.error(
        reason && TEST_REASONS.includes(reason)
          ? t(`admin.email.testFailed.${reason}`, 'The test e-mail could not be sent')
          : t('admin.email.testFailed', 'The test e-mail could not be sent')
      )
    } finally {
      setTesting(false)
    }
  }

  const field = (
    key: 'host' | 'port' | 'username' | 'from' | 'fromName',
    label: string,
    props: Record<string, unknown> = {}
  ) => (
    <SettingsField id={`${id}-${key}`} label={label}>
      {(control) => (
        <Input
          {...control}
          value={form[key]}
          onChange={(e) => set(key, e.target.value)}
          disabled={!canEdit}
          {...props}
        />
      )}
    </SettingsField>
  )

  return (
    <>
      <SettingsSection
        framed
        id="platform-email"
        title={t('admin.email.title', 'Platform e-mail')}
        description={t(
          'admin.email.description',
          'The SMTP server for sign-up, invitation, verification and password e-mails. An organization with its own e-mail integration sends through that instead.'
        )}
      >
        <SettingsSwitchRow
          id={`${id}-enabled`}
          label={t('admin.email.enabled', 'Send e-mail')}
          hint={t(
            'admin.email.enabledHelp',
            'Off: no e-mail is sent; set-password links are shown to the administrator instead.'
          )}
          checked={form.enabled}
          onCheckedChange={(v) => set('enabled', v)}
          disabled={!canEdit}
        />
        <SettingsBlock>
          <SettingsFieldGrid>
            {field('host', t('admin.email.host', 'SMTP server'), {
              placeholder: 'smtp.example.com',
              autoComplete: 'off',
            })}
            {field('port', t('admin.email.port', 'Port'), {
              inputMode: 'numeric',
              placeholder: '587',
            })}
            {field('username', t('admin.email.username', 'User name'), { autoComplete: 'off' })}
            <SecretField
              label={t('admin.email.password', 'Password')}
              isSet={!!settings.password_set}
              value={password}
              onChange={setPassword}
              clear={clearPassword}
              onClear={setClearPassword}
              disabled={!canEdit}
            />
            {field('from', t('admin.email.from', 'Sender address'), {
              type: 'email',
              placeholder: 'noreply@example.com',
            })}
            {field('fromName', t('admin.email.fromName', 'Sender name'), {
              placeholder: brand.name,
            })}
          </SettingsFieldGrid>
        </SettingsBlock>
        <SettingsSwitchRow
          id={`${id}-starttls`}
          label={t('admin.email.starttls', 'Use STARTTLS')}
          hint={t(
            'admin.email.starttlsHelp',
            'Encrypt the connection to the server (TLS 1.2 or later). Leave on unless the server cannot do it.'
          )}
          checked={form.starttls}
          onCheckedChange={(v) => set('starttls', v)}
          disabled={!canEdit}
        />
        <SettingsBlock>
          <SettingsField
            id={`${id}-ca`}
            label={t('admin.email.ca', 'Internal CA certificate')}
            hint={t(
              'admin.email.caHelp',
              'Only if your mail server uses a certificate from your own certificate authority. Paste the CA certificate (PEM, certificates only, never a private key). It is used only to verify this server and is never shown again.'
            )}
          >
            {(control) => (
              <Textarea
                {...control}
                value={caPem}
                onChange={(e) => {
                  setCaPem(e.target.value)
                  setClearCa(false)
                }}
                disabled={!canEdit || clearCa}
                rows={4}
                spellCheck={false}
                autoComplete="off"
                className="font-mono text-code"
                placeholder={
                  settings.ca_set
                    ? t('admin.email.caKeep', 'Stored. Paste a new PEM bundle to replace it.')
                    : '-----BEGIN CERTIFICATE-----'
                }
              />
            )}
          </SettingsField>
          {settings.ca_set && (
            <p className="text-cap text-muted-foreground">
              {t('admin.email.caFingerprint', 'Stored bundle fingerprint (SHA-256): {fp}').replace(
                '{fp}',
                settings.ca_fingerprint ?? ''
              )}
            </p>
          )}
          {settings.ca_set && canEdit && (
            <label className="flex items-center gap-2 text-dense text-muted-foreground">
              <input
                type="checkbox"
                checked={clearCa}
                onChange={(e) => {
                  setClearCa(e.target.checked)
                  setCaPem('')
                }}
              />
              {t('admin.email.caClear', 'Remove the stored CA certificate')}
            </label>
          )}
        </SettingsBlock>
        {/* Shown only when it can run: e-mail on and the form saved. */}
        {canEdit && settings.enabled && !dirty && (
          <SettingsRow
            label={t('admin.email.sendTest', 'Send a test e-mail')}
            hint={t(
              'admin.email.sendTestHint',
              'Sends an e-mail to your address with the saved settings. Save your changes first.'
            )}
          >
            <Button variant="outline" onClick={() => void test()} disabled={testing}>
              {testing && <Loader2 className="animate-spin" aria-hidden />}
              {t('admin.email.sendTestButton', 'Send test')}
            </Button>
          </SettingsRow>
        )}
      </SettingsSection>
      {canEdit && (
        <SettingsSaveBar
          dirty={dirty}
          saving={busy}
          onSave={() => setConfirmOpen(true)}
          onDiscard={reset}
        />
      )}

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={(open) => {
          if (!busy) setConfirmOpen(open)
        }}
        title={t('admin.email.confirmTitle', 'Change the platform e-mail settings?')}
        desc={t(
          'admin.email.confirmDesc',
          'The change applies to every e-mail sent from now on and is recorded in the admin audit log (without the password).'
        )}
        disabled={!rc.codeOk}
        isLoading={busy}
        handleConfirm={() => void save()}
        confirmText={
          busy ? (
            <>
              <Loader2 className="me-1.5 size-4 animate-spin" />
              {t('admin.email.saving', 'Saving')}
            </>
          ) : (
            t('admin.email.confirm', 'Confirm')
          )
        }
      >
        <ReasonAndCodeFields id={`${id}-code`} state={rc} withReason={false} />
      </ConfirmDialog>
    </>
  )
}
