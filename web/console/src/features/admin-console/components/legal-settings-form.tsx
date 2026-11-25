'use client'

import { useCallback, useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import {
  SettingsBlock,
  SettingsField,
  SettingsFieldGrid,
  SettingsSaveBar,
  SettingsSection,
  SettingsSwitchRow,
} from '@/features/shared'
import type { LegalSettingsResponse } from '@/lib/api/generated'
import { AdminApiError } from '@console/lib/admin-api/client'
import { saveLegalSettings } from '../api/use-legal-settings'
import { ReasonAndCodeFields, useReasonAndCode } from './step-up-code-hint'

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
  const rc = useReasonAndCode(confirmOpen)
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
    rc.setCodeError(null)
    try {
      await saveLegalSettings({
        ...form,
        version: settings.version ?? 0,
        totp_code: rc.code.trim(),
      })
      setConfirmOpen(false)
      toast.success(t('admin.legal.saved', 'Legal settings saved'))
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
    <SettingsField key={k} id={`${id}-${k}`} label={label[k]}>
      {(control) => (
        <Input
          {...control}
          value={form[k]}
          onChange={(e) => setForm((f) => ({ ...f, [k]: e.target.value }))}
          disabled={!canEdit}
        />
      )}
    </SettingsField>
  )
  const fields = (keys: TextKey[]) => (
    <SettingsBlock>
      <SettingsFieldGrid>{keys.map(text)}</SettingsFieldGrid>
    </SettingsBlock>
  )

  return (
    <>
      <SettingsSection
        framed
        id="legal-links"
        title={t('admin.legal.linksTitle', 'Sign-in page links')}
        description={t(
          'admin.legal.linksDescription',
          'The terms and privacy links on the sign-in and sign-up pages. Empty fields use the built-in pages.'
        )}
      >
        {fields(['terms_url', 'privacy_url'])}
      </SettingsSection>

      <SettingsSection
        framed
        id="legal-pages"
        title={t('admin.legal.pagesTitle', 'Built-in legal pages')}
        description={t(
          'admin.legal.pagesDescription',
          'The values the built-in pages are written from.'
        )}
      >
        <SettingsSwitchRow
          label={t('admin.legal.pagesEnabled', 'Serve the built-in legal pages')}
          hint={t(
            'admin.legal.pagesEnabledHelp',
            '/terms, /acceptable-use, /privacy, /dpa and /subprocessors from the values below. A starting point to review with counsel, not legal advice.'
          )}
          checked={form.pages_enabled}
          onCheckedChange={(v) => setForm((f) => ({ ...f, pages_enabled: v }))}
          disabled={!canEdit}
        />
        {fields([
          'organization_name',
          'service_name',
          'contact_email',
          'website_url',
          'docs_url',
          'address',
          'jurisdiction',
          'effective_date',
        ])}
      </SettingsSection>

      <SettingsSection
        framed
        id="legal-security"
        title={t('admin.legal.securityTitle', 'Security contact')}
        description={t(
          'admin.legal.securityDescription',
          'Where researchers report a vulnerability.'
        )}
      >
        {fields(['security_contact', 'security_policy_url'])}
        <SettingsSwitchRow
          label={t('admin.legal.securityTxt', 'Serve /.well-known/security.txt')}
          hint={t(
            'admin.legal.securityTxtHelp',
            'Tells researchers where to report a vulnerability (RFC 9116).'
          )}
          checked={!form.security_txt_disabled}
          onCheckedChange={(v) => setForm((f) => ({ ...f, security_txt_disabled: !v }))}
          disabled={!canEdit}
        />
      </SettingsSection>

      <SettingsSection
        framed
        id="legal-help"
        title={t('admin.legal.helpTitle', 'Help links')}
        description={t(
          'admin.legal.helpDescription',
          'Where Help > Report a bug and Send feedback lead. Empty fields use the project issue forms. Reports of a security vulnerability always go to the security contact and policy above.'
        )}
      >
        {fields(['help_bug_url', 'help_feedback_url'])}
        <SettingsSwitchRow
          label={t('admin.legal.helpLinksShown', 'Show Report a bug and Send feedback')}
          hint={t(
            'admin.legal.helpLinksShownHelp',
            'Off hides both entries, and the Report this problem link on error pages. Copy diagnostics stays.'
          )}
          checked={!form.help_links_disabled}
          onCheckedChange={(v) => setForm((f) => ({ ...f, help_links_disabled: !v }))}
          disabled={!canEdit}
        />
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
        title={t('admin.legal.confirmTitle', 'Change the legal information?')}
        desc={t(
          'admin.legal.confirmDesc',
          'Visitors see the change within a minute. It is recorded in the admin audit log.'
        )}
        disabled={!rc.codeOk}
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
        <ReasonAndCodeFields id={`${id}-code`} state={rc} withReason={false} />
      </ConfirmDialog>
    </>
  )
}
