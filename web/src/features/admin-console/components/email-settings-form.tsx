'use client'

import { useBrand } from '@/context/brand-provider'
import { useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import type { EmailSettingsResponse } from '@/lib/api/generated'
import { AdminApiError } from '../api/admin-client'
import { saveEmailSettings, sendTestEmail } from '../api/use-email-settings'

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
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [code, setCode] = useState('')
  const [codeError, setCodeError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [testing, setTesting] = useState(false)

  useEffect(() => {
    setForm(toForm(settings))
    setPassword('')
    setClearPassword(false)
  }, [settings])

  const set = <K extends keyof FormState>(k: K, v: FormState[K]) =>
    setForm((f) => ({ ...f, [k]: v }))
  const original = toForm(settings)
  const dirty =
    password !== '' ||
    clearPassword ||
    (Object.keys(form) as (keyof FormState)[]).some((k) => form[k] !== original[k])

  const save = async () => {
    setBusy(true)
    setCodeError(null)
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
        version: settings.version ?? 0,
        totp_code: code.trim(),
      })
      setConfirmOpen(false)
      toast.success(t('admin.email.saved', 'E-mail settings saved'))
      onSaved()
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        setCodeError(e.message)
        setCode('')
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
      toast.error(
        e instanceof Error
          ? e.message
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
    <div className="grid gap-1.5">
      <Label htmlFor={`${id}-${key}`}>{label}</Label>
      <Input
        id={`${id}-${key}`}
        value={form[key]}
        onChange={(e) => set(key, e.target.value)}
        disabled={!canEdit}
        {...props}
      />
    </div>
  )

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>{t('admin.email.title', 'Platform e-mail')}</CardTitle>
          <CardDescription>
            {t(
              'admin.email.description',
              'The SMTP server for sign-up, invitation, verification and password e-mails. An organization with its own e-mail integration sends through that instead.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="flex items-start justify-between gap-4 rounded-lg border p-4">
            <Label htmlFor={`${id}-enabled`} className="grid gap-1 font-normal">
              <span className="font-medium">{t('admin.email.enabled', 'Send e-mail')}</span>
              <span className="text-sm text-muted-foreground">
                {t(
                  'admin.email.enabledHelp',
                  'Off: no e-mail is sent; set-password links are shown to the administrator instead.'
                )}
              </span>
            </Label>
            <Switch
              id={`${id}-enabled`}
              checked={form.enabled}
              onCheckedChange={(v) => set('enabled', v)}
              disabled={!canEdit}
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            {field('host', t('admin.email.host', 'SMTP server'), {
              placeholder: 'smtp.example.com',
              autoComplete: 'off',
            })}
            {field('port', t('admin.email.port', 'Port'), {
              inputMode: 'numeric',
              placeholder: '587',
            })}
            {field('username', t('admin.email.username', 'User name'), { autoComplete: 'off' })}
            <div className="grid gap-1.5">
              <Label htmlFor={`${id}-password`}>{t('admin.email.password', 'Password')}</Label>
              <Input
                id={`${id}-password`}
                type="password"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value)
                  setClearPassword(false)
                }}
                disabled={!canEdit || clearPassword}
                autoComplete="new-password"
                placeholder={
                  settings.password_set
                    ? t('admin.email.passwordKeep', 'Stored. Type to replace it.')
                    : t('admin.email.passwordNone', 'Not set')
                }
              />
              {settings.password_set && canEdit && (
                <label className="flex items-center gap-2 text-sm text-muted-foreground">
                  <input
                    type="checkbox"
                    checked={clearPassword}
                    onChange={(e) => {
                      setClearPassword(e.target.checked)
                      setPassword('')
                    }}
                  />
                  {t('admin.email.passwordClear', 'Remove the stored password')}
                </label>
              )}
            </div>
            {field('from', t('admin.email.from', 'Sender address'), {
              type: 'email',
              placeholder: 'noreply@example.com',
            })}
            {field('fromName', t('admin.email.fromName', 'Sender name'), {
              placeholder: brand.name,
            })}
          </div>

          <div className="flex items-start justify-between gap-4 rounded-lg border p-4">
            <Label htmlFor={`${id}-starttls`} className="grid gap-1 font-normal">
              <span className="font-medium">{t('admin.email.starttls', 'Use STARTTLS')}</span>
              <span className="text-sm text-muted-foreground">
                {t(
                  'admin.email.starttlsHelp',
                  'Encrypt the connection to the server (TLS 1.2 or later). Leave on unless the server cannot do it.'
                )}
              </span>
            </Label>
            <Switch
              id={`${id}-starttls`}
              checked={form.starttls}
              onCheckedChange={(v) => set('starttls', v)}
              disabled={!canEdit}
            />
          </div>

          <div className="flex flex-wrap items-center justify-end gap-3">
            {canEdit && (
              <Button
                variant="outline"
                onClick={() => void test()}
                disabled={testing || dirty || !settings.enabled}
              >
                {testing && <Loader2 className="me-1.5 size-4 animate-spin" />}
                {t('admin.email.sendTest', 'Send a test e-mail')}
              </Button>
            )}
            {canEdit && (
              <Button
                onClick={() => {
                  setCode('')
                  setCodeError(null)
                  setConfirmOpen(true)
                }}
                disabled={!dirty || busy}
              >
                {t('admin.email.save', 'Save')}
              </Button>
            )}
          </div>
          {!canEdit && (
            <p className="text-sm text-muted-foreground">
              {t('admin.email.superAdminOnly', 'Only a super admin can change these settings.')}
            </p>
          )}
        </CardContent>
      </Card>

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
        disabled={code.trim().length < 6}
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
        <div className="space-y-2">
          <Label htmlFor={`${id}-code`}>
            {t('admin.email.code', 'Code from your authenticator')}
          </Label>
          <Input
            id={`${id}-code`}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={8}
            aria-invalid={!!codeError}
          />
          {codeError && <p className="text-sm text-destructive">{codeError}</p>}
        </div>
      </ConfirmDialog>
    </>
  )
}
