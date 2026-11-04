'use client'

import { useCallback, useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsSaveBar } from '@/features/shared/components/settings-save-bar'
import type { LegalSettingsResponse } from '@/lib/api/generated'
import { AdminApiError } from '@console/lib/admin-api/client'
import { saveLegalSettings } from '../api/use-legal-settings'
import { StepUpCodeField, stepUpCodeReady, useStepUpCodeOptional } from './step-up-code-hint'

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
  | 'help_bug_url'
  | 'help_feedback_url'

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
  'help_bug_url',
  'help_feedback_url',
]

interface FormState extends Record<TextKey, string> {
  pages_enabled: boolean
  security_txt_disabled: boolean
  help_links_disabled: boolean
}

function toForm(s: LegalSettingsResponse): FormState {
  const f = {
    pages_enabled: !!s.pages_enabled,
    security_txt_disabled: !!s.security_txt_disabled,
    help_links_disabled: !!s.help_links_disabled,
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

  // The saved values: on load, after a save and on Discard.
  const reset = useCallback(() => setForm(toForm(settings)), [settings])
  useEffect(reset, [reset])

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
    help_bug_url: t('admin.legal.helpBugUrl', 'Report a bug link (https)'),
    help_feedback_url: t('admin.legal.helpFeedbackUrl', 'Send feedback link (https)'),
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

          <div className="space-y-4">
            <div className="grid gap-1">
              <h3 className="text-sm font-medium">{t('admin.legal.helpTitle', 'Help links')}</h3>
              <p className="text-sm text-muted-foreground">
                {t(
                  'admin.legal.helpDescription',
                  'Where Help > Report a bug and Send feedback lead. Empty fields use the project issue forms. Reports of a security vulnerability always go to the security contact and policy above.'
                )}
              </p>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              {(['help_bug_url', 'help_feedback_url'] as TextKey[]).map(text)}
            </div>
            <div className="flex items-start justify-between gap-4 rounded-lg border p-4">
              <Label htmlFor={`${id}-helphide`} className="grid gap-1 font-normal">
                <span className="font-medium">
                  {t('admin.legal.helpLinksShown', 'Show Report a bug and Send feedback')}
                </span>
                <span className="text-sm text-muted-foreground">
                  {t(
                    'admin.legal.helpLinksShownHelp',
                    'Off hides both entries, and the Report this problem link on error pages. Copy diagnostics stays.'
                  )}
                </span>
              </Label>
              <Switch
                id={`${id}-helphide`}
                checked={!form.help_links_disabled}
                onCheckedChange={(v) => setForm((f) => ({ ...f, help_links_disabled: !v }))}
                disabled={!canEdit}
              />
            </div>
          </div>

          <div className="flex justify-end">
            {canEdit && (
              <SettingsSaveBar
                className="basis-full"
                dirty={dirty}
                saving={busy}
                onSave={() => {
                  setCode('')
                  setCodeError(null)
                  setConfirmOpen(true)
                }}
                onDiscard={reset}
              />
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
        <StepUpCodeField
          id={`${id}-code`}
          value={code}
          onChange={setCode}
          optional={codeOptional}
          error={codeError}
        />
      </ConfirmDialog>
    </>
  )
}
