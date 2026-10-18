'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { AlertCircle, ShieldHalf } from 'lucide-react'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { PageHeader, ReadOnlyNotice, SettingsSaveBar } from '@/features/shared'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Separator } from '@/components/ui/separator'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useCanMutate } from '@/lib/permissions'
import { SsoManagedNotice } from '@/features/sso/components/sso-managed-by-platform'
import { useTenantSettings, useUpdateSecuritySettings } from '../api/use-tenant-settings'
import type {
  InviteesPolicy,
  PersonalAccountsPolicy,
  SSOException,
  TenantSettings,
} from '../types/settings.types'
import { AccessRestrictionsCard, isIpLockoutError, parseLines } from './access-restrictions-card'
import { InvitationPolicyCard } from './invitation-policy-card'
import { LastChanged } from './last-changed'
import { PersonalAccountsCard } from './personal-accounts-card'
import { SettingsLoadError, SettingsLoading } from './settings-load-state'

type EmailVerificationMode = 'auto' | 'always' | 'never'

/** The sign-in part of the security section: what this page edits. */
export interface SignInForm {
  mfa_required: boolean
  mfa_required_for_admins: boolean
  ip_whitelist: string
  allowed_domains: string
  email_verification_mode: EmailVerificationMode
  personal_accounts: PersonalAccountsPolicy
  invitees: InviteesPolicy
  external_access_end_required: boolean
  sso_exceptions: SSOException[]
  jit_requires_approval: boolean
}

/** The fields this page saves, for "last changed by". */
export const SIGN_IN_FIELDS = [
  'mfa_required',
  'mfa_required_for_admins',
  'ip_whitelist',
  'allowed_domains',
  'email_verification_mode',
  'personal_accounts',
  'invitees',
  'external_access_end_required',
  'sso_exceptions',
  'jit_requires_approval',
] as const

export function signInFormFrom(settings: TenantSettings | undefined): SignInForm {
  const s = settings?.security
  return {
    mfa_required: s?.mfa_required ?? false,
    mfa_required_for_admins: s?.mfa_required_for_admins ?? false,
    ip_whitelist: (s?.ip_whitelist ?? []).join('\n'),
    allowed_domains: (s?.allowed_domains ?? []).join('\n'),
    email_verification_mode: (s?.email_verification_mode as EmailVerificationMode) || 'auto',
    personal_accounts: s?.personal_accounts ?? 'allowed',
    invitees: s?.invitees ?? 'any',
    external_access_end_required: s?.external_access_end_required ?? false,
    sso_exceptions: s?.sso_exceptions ?? [],
    jit_requires_approval: s?.jit_requires_approval ?? false,
  }
}

/** Compare two forms the way the API stores them (lines trimmed, blanks dropped). */
function normalized(f: SignInForm) {
  return JSON.stringify({
    ...f,
    ip_whitelist: parseLines(f.ip_whitelist),
    allowed_domains: parseLines(f.allowed_domains),
  })
}

const PERSONAL_ORDER: Record<PersonalAccountsPolicy, number> = {
  blocked: 0,
  allowed_with_mfa: 1,
  allowed: 2,
}

/**
 * The changes in `next` that weaken sign-in protection compared with `saved`,
 * as i18n keys. They are confirmed before saving; the API also grades them
 * High/Critical in the audit log and tells the owners and administrators.
 */
export function looseningsOf(saved: SignInForm, next: SignInForm): string[] {
  const out: string[] = []
  if (saved.mfa_required && !next.mfa_required) out.push('mfaOff')
  if (
    (saved.mfa_required || saved.mfa_required_for_admins) &&
    !(next.mfa_required || next.mfa_required_for_admins)
  ) {
    out.push('mfaAdminsOff')
  }
  const ipBefore = parseLines(saved.ip_whitelist)
  const ipAfter = parseLines(next.ip_whitelist)
  if (ipBefore.length > 0 && ipAfter.length === 0) out.push('ipEmptied')
  else if (ipBefore.length > 0 && ipAfter.some((x) => !ipBefore.includes(x))) out.push('ipWidened')
  const dBefore = parseLines(saved.allowed_domains)
  const dAfter = parseLines(next.allowed_domains)
  if (dBefore.length > 0 && (dAfter.length === 0 || dAfter.some((x) => !dBefore.includes(x)))) {
    out.push('domainsWidened')
  }
  if (saved.email_verification_mode !== 'never' && next.email_verification_mode === 'never') {
    out.push('emailNever')
  }
  if (PERSONAL_ORDER[next.personal_accounts] > PERSONAL_ORDER[saved.personal_accounts]) {
    out.push('personalLooser')
  }
  if (saved.jit_requires_approval && !next.jit_requires_approval) out.push('jitOff')
  if (next.sso_exceptions.some((e) => !saved.sso_exceptions.some((s) => s.user_id === e.user_id))) {
    out.push('ssoExceptionAdded')
  }
  if (saved.invitees !== 'any' && next.invitees === 'any') out.push('inviteesAny')
  if (saved.external_access_end_required && !next.external_access_end_required) {
    out.push('externalEndOff')
  }
  return out
}

const LOOSENING_TEXT: Record<string, string> = {
  mfaOff: 'Two-factor authentication is no longer required for everyone.',
  mfaAdminsOff: 'Owners and administrators no longer need two-factor authentication.',
  ipEmptied: 'The IP allowlist is emptied: every network may connect.',
  ipWidened: 'The IP allowlist allows more networks.',
  domainsWidened: 'More email domains may join.',
  emailNever: 'Email addresses are no longer verified.',
  personalLooser: 'Personal accounts get more access.',
  jitOff: 'New SSO members get access without approval.',
  ssoExceptionAdded: 'More members may sign in without single sign-on.',
  inviteesAny: 'Anyone may be invited.',
  externalEndOff: 'External members no longer need an end date.',
}

/**
 * Security › Authentication: how people sign in to the organization and who
 * may join. One sticky Save; the API (owner only, recent sign-in) refuses an
 * IP allowlist that would lock the saver out. Changes that weaken protection
 * are listed and confirmed first.
 */
export function AuthenticationSettings() {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id
  // Owner only on the backend (RequireTeamOwner + step-up).
  const canEdit = useCanMutate('PATCH /api/v1/tenants/{tenant}/settings/security')
  const { settings, isLoading, isError, error, mutate } = useTenantSettings(tenantId)
  const { updateSecuritySettings, isUpdating } = useUpdateSecuritySettings(tenantId)

  const saved = useMemo(() => signInFormFrom(settings), [settings])
  const [form, setForm] = useState<SignInForm>(saved)
  const [ipError, setIpError] = useState<string | null>(null)
  const [confirm, setConfirm] = useState<string[] | null>(null)

  const reset = useCallback(() => {
    setForm(saved)
    setIpError(null)
  }, [saved])
  useEffect(() => {
    reset()
  }, [reset])

  const dirty = normalized(form) !== normalized(saved)
  const patchForm = (p: Partial<SignInForm>) => setForm((f) => ({ ...f, ...p }))

  const doSave = async () => {
    setConfirm(null)
    setIpError(null)
    try {
      const result = await updateSecuritySettings({
        mfa_required: form.mfa_required,
        mfa_required_for_admins: form.mfa_required_for_admins,
        ip_whitelist: parseLines(form.ip_whitelist),
        allowed_domains: parseLines(form.allowed_domains),
        email_verification_mode: form.email_verification_mode,
        personal_accounts: form.personal_accounts,
        invitees: form.invitees,
        external_access_end_required: form.external_access_end_required,
        sso_exceptions: form.sso_exceptions,
        jit_requires_approval: form.jit_requires_approval,
      })
      if (result) await mutate(result, { revalidate: false })
      toast.success(t('org.auth.saved', 'Sign-in settings saved'))
    } catch (err) {
      // The API refuses an allowlist that would lock the saver out: show it
      // next to the field, not only in a toast.
      if (isIpLockoutError(err)) setIpError(err.message)
      toast.error(
        getErrorMessage(err, t('org.auth.saveFailed', 'Could not save the sign-in settings'))
      )
    }
  }

  const handleSave = () => {
    const loosened = looseningsOf(saved, form)
    if (loosened.length > 0) setConfirm(loosened)
    else void doSave()
  }

  const header = (
    <PageHeader
      title={t('org.auth.title', 'Authentication')}
      description={t('org.auth.desc', 'How people sign in to this organization, and who may join.')}
    />
  )
  if (isLoading) return <SettingsLoading header={header} />
  if (isError)
    return (
      <SettingsLoadError header={header} message={error?.message} onRetry={() => void mutate()} />
    )

  const disabled = !canEdit
  const emailModes: { value: EmailVerificationMode; label: string; hint: string }[] = [
    {
      value: 'auto',
      label: t('org.auth.email.auto', 'Auto (recommended)'),
      hint: t('org.auth.email.autoHint', 'Require verification when the platform can send email'),
    },
    {
      value: 'always',
      label: t('org.auth.email.always', 'Always require'),
      hint: t(
        'org.auth.email.alwaysHint',
        'Require verification (the platform must be able to send email)'
      ),
    },
    {
      value: 'never',
      label: t('org.auth.email.never', 'Never require'),
      hint: t(
        'org.auth.email.neverHint',
        'Accounts count as verified at registration: closed deployments only'
      ),
    },
  ]

  return (
    <Main>
      {header}
      <div className="mt-2">
        <LastChanged resourceType="tenant" resourceId={tenantId} fields={SIGN_IN_FIELDS} />
      </div>
      {disabled && (
        <ReadOnlyNotice
          className="mt-4"
          reason={t('org.auth.ownerOnly', 'Only the organization owner can change these settings.')}
        />
      )}

      <div className="mt-5 space-y-5">
        <Card id="two-factor">
          <CardHeader>
            <CardTitle>{t('org.auth.mfa.title', 'Two-factor authentication')}</CardTitle>
            <CardDescription>
              {t(
                'org.auth.mfa.desc',
                "Members who sign in through SSO use your identity provider's two-factor settings."
              )}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <ToggleRow
              id="tenant-mfa-required"
              label={t('org.auth.mfa.all', 'Require for everyone')}
              hint={t(
                'org.auth.mfa.allHint',
                'Members who sign in with a password set up an authenticator app at their next sign-in.'
              )}
              checked={form.mfa_required}
              onChange={(v) => patchForm({ mfa_required: v })}
              disabled={disabled}
            />
            <ToggleRow
              id="tenant-mfa-admins"
              label={t('org.auth.mfa.admins', 'Require for owners and administrators')}
              hint={t(
                'org.auth.mfa.adminsHint',
                'They can change the organization, so they use an authenticator app even when other members do not. On for new organizations.'
              )}
              checked={form.mfa_required || form.mfa_required_for_admins}
              onChange={(v) => patchForm({ mfa_required_for_admins: v })}
              disabled={disabled || form.mfa_required}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>{t('org.auth.newMembers.title', 'New members')}</CardTitle>
            <CardDescription>
              {t('org.auth.newMembers.desc', 'What happens when someone joins for the first time.')}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div id="sso-member-approval">
              <ToggleRow
                id="tenant-jit-approval"
                label={t('org.auth.jit', 'Approve new SSO members')}
                hint={t(
                  'org.auth.jitHint',
                  'People your SSO admits for the first time wait, with no access, until an administrator approves them in Members.'
                )}
                checked={form.jit_requires_approval}
                onChange={(v) => patchForm({ jit_requires_approval: v })}
                disabled={disabled}
              />
            </div>
            <Separator />
            <div id="email-verification" className="space-y-2">
              <Label htmlFor="email-verification-mode">
                {t('org.auth.email.title', 'Email verification')}
              </Label>
              <p className="text-sm text-muted-foreground" id="email-verification-desc">
                {t(
                  'org.auth.email.desc',
                  'Whether new accounts must verify their email address before signing in.'
                )}
              </p>
              <Select
                value={form.email_verification_mode}
                onValueChange={(v) =>
                  patchForm({ email_verification_mode: v as EmailVerificationMode })
                }
                disabled={disabled}
              >
                <SelectTrigger
                  id="email-verification-mode"
                  aria-describedby="email-verification-desc"
                  className="w-full max-w-md"
                >
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {emailModes.map((m) => (
                    <SelectItem key={m.value} value={m.value}>
                      <div className="flex flex-col items-start">
                        <span className="font-medium">{m.label}</span>
                        <span className="text-xs text-muted-foreground">{m.hint}</span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {form.email_verification_mode === 'never' && (
                <p className="mt-2 flex items-start gap-2 text-sm text-destructive" role="alert">
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
                  <span>
                    {t(
                      'org.auth.email.neverWarning',
                      'Anyone can register with any email address, which allows account takeover through spoofed addresses. Use it only where registration is restricted by other means.'
                    )}
                  </span>
                </p>
              )}
            </div>
          </CardContent>
        </Card>

        <AccessRestrictionsCard
          ipAllowlist={form.ip_whitelist}
          allowedDomains={form.allowed_domains}
          onIpAllowlistChange={(v) => {
            setIpError(null)
            patchForm({ ip_whitelist: v })
          }}
          onAllowedDomainsChange={(v) => patchForm({ allowed_domains: v })}
          currentIp={settings?.security?.current_ip}
          ipAllowlistError={ipError}
          disabled={disabled}
        />
        <div id="invitations">
          <InvitationPolicyCard
            invitees={form.invitees}
            onInviteesChange={(p) => patchForm({ invitees: p })}
            endRequired={form.external_access_end_required}
            onEndRequiredChange={(v) => patchForm({ external_access_end_required: v })}
            hasAllowedDomains={parseLines(form.allowed_domains).length > 0}
            disabled={disabled}
          />
        </div>
        <div id="personal-accounts">
          <PersonalAccountsCard
            tenantSlug={tenantId}
            policy={form.personal_accounts}
            onPolicyChange={(p) => patchForm({ personal_accounts: p })}
            exceptions={form.sso_exceptions}
            onExceptionsChange={(e) => patchForm({ sso_exceptions: e })}
            ssoEnforced={!!settings?.security?.sso_enforced}
            disabled={disabled}
          />
        </div>
        <SsoManagedNotice />

        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <ShieldHalf className="size-4 shrink-0" aria-hidden />
          <span>
            {t('org.auth.sensorMoved', 'What scan jobs may do on your sensors is set in')}{' '}
            <Link
              href="/settings/scanning/sensor-safety"
              className="font-medium underline-offset-2 hover:underline"
            >
              {t('settings.item.sensor-safety', 'Sensor job safety')}
            </Link>
            .
          </span>
        </p>
      </div>

      <SettingsSaveBar dirty={dirty} saving={isUpdating} onSave={handleSave} onDiscard={reset} />

      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(open) => !open && setConfirm(null)}
        destructive
        title={t('org.auth.loosen.title', 'Weaken sign-in security?')}
        desc={
          <div className="space-y-2">
            <p>
              {t(
                'org.auth.loosen.desc',
                'These changes make the organization easier to get into. The owner and administrators are told, and the change is recorded in the audit log.'
              )}
            </p>
            <ul className="list-disc space-y-1 ps-5">
              {(confirm ?? []).map((k) => (
                <li key={k}>{t(`org.auth.loosen.${k}`, LOOSENING_TEXT[k] ?? k)}</li>
              ))}
            </ul>
          </div>
        }
        confirmText={t('org.auth.loosen.confirm', 'Save anyway')}
        isLoading={isUpdating}
        handleConfirm={() => void doSave()}
      />
    </Main>
  )
}

function ToggleRow({
  id,
  label,
  hint,
  checked,
  onChange,
  disabled,
}: {
  id: string
  label: string
  hint: string
  checked: boolean
  onChange: (v: boolean) => void
  disabled?: boolean
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div className="space-y-0.5">
        <Label htmlFor={id}>{label}</Label>
        <p className="text-sm text-muted-foreground" id={`${id}-desc`}>
          {hint}
        </p>
      </div>
      <Switch
        id={id}
        aria-describedby={`${id}-desc`}
        checked={checked}
        onCheckedChange={onChange}
        disabled={disabled}
      />
    </div>
  )
}
