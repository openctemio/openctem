'use client'

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
import type { LegalSettingsResponse } from '@/lib/api/generated'
import { AdminApiError } from '@console/lib/admin-api/client'
import { saveLegalSettings } from '../api/use-legal-settings'
import { StepUpCodeHint, stepUpCodeReady, useStepUpCodeOptional } from './step-up-code-hint'

type TextKey =
  | 'terms_url'
  | 'privacy_url'
  | 'organization_name'
  | 'service_name'
  | 'contact_email'
  | 'website_url'
  | 'docs_url'
  | 'address'
  | 'jurisdiction'
  | 'effective_date'
  | 'security_contact'
  | 'security_policy_url'

const TEXT_KEYS: TextKey[] = [
  'terms_url',
  'privacy_url',
  'organization_name',
  'service_name',
  'contact_email',
  'website_url',
  'docs_url',
  'address',
  'jurisdiction',
  'effective_date',
  'security_contact',
  'security_policy_url',
]

interface FormState extends Record<TextKey, string> {
  pages_enabled: boolean
  security_txt_disabled: boolean
}

function toForm(s: LegalSettingsResponse): FormState {
  const f = {
    pages_enabled: !!s.pages_enabled,
    security_txt_disabled: !!s.security_txt_disabled,
  } as FormState
  for (const k of TEXT_KEYS) f[k] = (s[k] as string | undefined) ?? ''
  return f
}

export interface LegalSettingsFormProps {
  settings: LegalSettingsResponse
  canEdit: boolean
  onSaved: () => void
}

/**
 * System > Legal: the links shown on the sign-in and sign-up pages, the values
 * of the built-in legal pages and the security.txt contact. Everything here is
 * public; a save needs a fresh authenticator code.
 */
export function LegalSettingsForm({ settings, canEdit, onSaved }: LegalSettingsFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const [form, setForm] = useState<FormState>(() => toForm(settings))
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [code, setCode] = useState('')
  const codeOptional = useStepUpCodeOptional()
  const [codeError, setCodeError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => setForm(toForm(settings)), [settings])

  const original = toForm(settings)
  const dirty = (Object.keys(form) as (keyof FormState)[]).some((k) => form[k] !== original[k])

  const label: Record<TextKey, string> = {
    terms_url: t('admin.legal.termsUrl', 'Terms of service link (https)'),
    privacy_url: t('admin.legal.privacyUrl', 'Privacy policy link (https)'),
    organization_name: t('admin.legal.organizationName', 'Legal name of the operator'),
    service_name: t('admin.legal.serviceName', 'Service name'),
    contact_email: t('admin.legal.contactEmail', 'Contact e-mail'),
    website_url: t('admin.legal.websiteUrl', 'Website (https)'),
    docs_url: t('admin.legal.docsUrl', 'Documentation (https)'),
    address: t('admin.legal.address', 'Postal address'),
    jurisdiction: t('admin.legal.jurisdiction', 'Governing law'),
    effective_date: t('admin.legal.effectiveDate', 'Effective date'),
    security_contact: t('admin.legal.securityContact', 'Security contact (e-mail or https URL)'),
    security_policy_url: t('admin.legal.securityPolicyUrl', 'Security policy link (https)'),
  }

  const save = async () => {
    setBusy(true)
    setCodeError(null)
    try {
      await saveLegalSettings({ ...form, version: settings.version ?? 0, totp_code: code.trim() })
      setConfirmOpen(false)
      toast.success(t('admin.legal.saved', 'Legal settings saved'))
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
            'admin.legal.conflict',
            'Another administrator changed the settings. The latest values are shown.'
          )
        )
        onSaved()
        return
      }
      toast.error(
        e instanceof Error
          ? e.message
          : t('admin.legal.saveFailed', 'Could not save the legal settings')
      )
    } finally {
      setBusy(false)
    }
  }

  const text = (k: TextKey) => (
    <div key={k} className="grid gap-1.5">
      <Label htmlFor={`${id}-${k}`}>{label[k]}</Label>
      <Input
        id={`${id}-${k}`}
        value={form[k]}
        onChange={(e) => setForm((f) => ({ ...f, [k]: e.target.value }))}
        disabled={!canEdit}
      />
    </div>
  )

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>{t('admin.legal.title', 'Legal information')}</CardTitle>
          <CardDescription>
            {t(
              'admin.legal.description',
              'Shown to visitors before they sign in: the links on the sign-in and sign-up pages, the built-in legal pages and /.well-known/security.txt. Empty fields use the defaults.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-2">
            {(['terms_url', 'privacy_url'] as TextKey[]).map(text)}
          </div>

          <div className="flex items-start justify-between gap-4 rounded-lg border p-4">
            <Label htmlFor={`${id}-pages`} className="grid gap-1 font-normal">
              <span className="font-medium">
                {t('admin.legal.pagesEnabled', 'Serve the built-in legal pages')}
              </span>
              <span className="text-sm text-muted-foreground">
                {t(
                  'admin.legal.pagesEnabledHelp',
                  '/terms, /acceptable-use, /privacy, /dpa and /subprocessors from the values below. A starting point to review with counsel, not legal advice.'
                )}
              </span>
            </Label>
            <Switch
              id={`${id}-pages`}
              checked={form.pages_enabled}
              onCheckedChange={(v) => setForm((f) => ({ ...f, pages_enabled: v }))}
              disabled={!canEdit}
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            {(
              [
                'organization_name',
                'service_name',
                'contact_email',
                'website_url',
                'docs_url',
                'address',
                'jurisdiction',
                'effective_date',
              ] as TextKey[]
            ).map(text)}
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            {(['security_contact', 'security_policy_url'] as TextKey[]).map(text)}
          </div>
          <div className="flex items-start justify-between gap-4 rounded-lg border p-4">
            <Label htmlFor={`${id}-sectxt`} className="grid gap-1 font-normal">
              <span className="font-medium">
                {t('admin.legal.securityTxt', 'Serve /.well-known/security.txt')}
              </span>
              <span className="text-sm text-muted-foreground">
                {t(
                  'admin.legal.securityTxtHelp',
                  'Tells researchers where to report a vulnerability (RFC 9116).'
                )}
              </span>
            </Label>
            <Switch
              id={`${id}-sectxt`}
              checked={!form.security_txt_disabled}
              onCheckedChange={(v) => setForm((f) => ({ ...f, security_txt_disabled: !v }))}
              disabled={!canEdit}
            />
          </div>

          <div className="flex justify-end">
            {canEdit && (
              <Button
                onClick={() => {
                  setCode('')
                  setCodeError(null)
                  setConfirmOpen(true)
                }}
                disabled={!dirty || busy}
              >
                {t('admin.legal.save', 'Save')}
              </Button>
            )}
          </div>
          {!canEdit && (
            <p className="text-sm text-muted-foreground">
              {t('admin.legal.superAdminOnly', 'Only a super admin can change these settings.')}
            </p>
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={(open) => {
          if (!busy) setConfirmOpen(open)
        }}
        title={t('admin.legal.confirmTitle', 'Change the legal information?')}
        desc={t(
          'admin.legal.confirmDesc',
          'Visitors see the change within a minute. It is recorded in the admin audit log.'
        )}
        disabled={!stepUpCodeReady(code, codeOptional)}
        isLoading={busy}
        handleConfirm={() => void save()}
        confirmText={
          busy ? (
            <>
              <Loader2 className="me-1.5 size-4 animate-spin" />
              {t('admin.legal.saving', 'Saving')}
            </>
          ) : (
            t('admin.legal.confirm', 'Confirm')
          )
        }
      >
        <div className="space-y-2">
          <Label htmlFor={`${id}-code`}>
            {t('admin.legal.code', 'Code from your authenticator')}
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
          <StepUpCodeHint optional={codeOptional} />
          {codeError && <p className="text-sm text-destructive">{codeError}</p>}
        </div>
      </ConfirmDialog>
    </>
  )
}
