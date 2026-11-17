'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from '@/components/link'
import { ShieldHalf } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  SettingsBlock,
  SettingsPage,
  SettingsRow,
  SettingsSaveBar,
  SettingsSection,
  SettingsSwitchRow,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { SETTINGS_ANCHOR_EVENT } from '@/config/settings-search'
import { useUnsavedChangesGuard } from '@/hooks/use-unsaved-changes-guard'
import { useUrlFilter } from '@/hooks/use-url-param'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useCanMutate, usePermissions } from '@/lib/permissions'
import { SsoManagedNotice } from '@/features/sso/components/sso-managed-by-platform'
import { SSOChangeApprovals } from '@/features/sso-approvals/components/sso-change-approvals'
import { useSSOChanges } from '@/features/sso-approvals/api/use-sso-changes'
import { useTenantSettings, useUpdateSecuritySettings } from '../api/use-tenant-settings'
import type {
  InviteesPolicy,
  PersonalAccountsPolicy,
  SSOException,
  StepUpPolicy,
  TenantSettings,
} from '../types/settings.types'
import {
  AllowedDomainsBlock,
  NetworkRestrictionSection,
  isIpLockoutError,
  parseLines,
} from './access-restrictions-card'
import { DomainSignupPolicies } from './domain-signup-policies'
import { InvitationPolicyCard } from './invitation-policy-card'
import { LastChanged } from './last-changed'
import { PersonalAccountsCard } from './personal-accounts-card'
import { LEGACY_STEP_UP, StepUpPolicyCard, stepUpLooser } from './step-up-policy-card'
import { TrustedOrganizations } from './trusted-organizations'

type EmailVerificationMode = 'auto' | 'always'

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
  sso_require_mfa_evidence: boolean
  step_up: StepUpPolicy
}

type SignInField = keyof SignInForm

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
  'sso_require_mfa_evidence',
  'step_up',
] as const satisfies readonly SignInField[]

export type SignInTab = 'sign-in' | 'joining'

/** Which tab edits (and saves) each field: every field belongs to exactly one. */
export const TAB_FIELDS: Record<SignInTab, readonly SignInField[]> = {
  'sign-in': [
    'mfa_required',
    'mfa_required_for_admins',
    'sso_require_mfa_evidence',
    'step_up',
    'email_verification_mode',
    'ip_whitelist',
  ],
  joining: [
    'invitees',
    'allowed_domains',
    'external_access_end_required',
    'jit_requires_approval',
    'personal_accounts',
    'sso_exceptions',
  ],
}

/**
 * `?tab=` values that open the Joining tab at one of its sections: the old
 * pages Domains, Trusted organizations and SSO approvals redirect here with
 * them (src/config/legacy-routes.ts).
 */
const TAB_SECTION: Record<string, string> = {
  domains: 'domains',
  'trusted-organizations': 'trusted-organizations',
  'sso-approvals': 'sso-approvals',
}

/** In-page anchors (settings search, the security overview) that live on the Joining tab. */
const JOINING_ANCHORS = new Set([
  'who-may-join',
  'invitations',
  'allowed-domains',
  'sso-member-approval',
  'personal-accounts',
  'sso-exceptions',
  'domains',
  'trusted-organizations',
  'trusted-by',
  'sso-approvals',
])

/** In-page anchors that live on the Sign-in tab. */
const SIGN_IN_ANCHORS = new Set([
  'two-factor',
  're-verification',
  'new-accounts',
  'email-verification',
  'network-restriction',
  'ip-allowlist',
  'single-sign-on',
])

export function signInFormFrom(settings: TenantSettings | undefined): SignInForm {
  const s = settings?.security
  return {
    mfa_required: s?.mfa_required ?? false,
    mfa_required_for_admins: s?.mfa_required_for_admins ?? false,
    ip_whitelist: (s?.ip_whitelist ?? []).join('\n'),
    allowed_domains: (s?.allowed_domains ?? []).join('\n'),
    email_verification_mode: s?.email_verification_mode === 'always' ? 'always' : 'auto',
    personal_accounts: s?.personal_accounts ?? 'allowed',
    invitees: s?.invitees ?? 'any',
    external_access_end_required: s?.external_access_end_required ?? false,
    sso_exceptions: s?.sso_exceptions ?? [],
    jit_requires_approval: s?.jit_requires_approval ?? false,
    sso_require_mfa_evidence: s?.sso_require_mfa_evidence ?? false,
    step_up: s?.step_up ?? LEGACY_STEP_UP,
  }
}

/** One field the way the API stores it (lines trimmed, blanks dropped). */
function fieldKey(f: SignInForm, k: SignInField): string {
  const v = f[k]
  return JSON.stringify(
    k === 'ip_whitelist' || k === 'allowed_domains' ? parseLines(v as string) : v
  )
}

/** The fields of `fields` whose value in `form` differs from `saved`. */
export function changedOf(
  saved: SignInForm,
  form: SignInForm,
  fields: readonly SignInField[]
): SignInField[] {
  return fields.filter((k) => fieldKey(saved, k) !== fieldKey(form, k))
}

/** `saved` with the given fields taken from `form`: what one tab sends. */
export function withFields(
  saved: SignInForm,
  form: SignInForm,
  fields: readonly SignInField[]
): SignInForm {
  const out = { ...saved } as Record<SignInField, unknown>
  for (const k of fields) out[k] = form[k]
  return out as unknown as SignInForm
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
  if (PERSONAL_ORDER[next.personal_accounts] > PERSONAL_ORDER[saved.personal_accounts]) {
    out.push('personalLooser')
  }
  if (saved.jit_requires_approval && !next.jit_requires_approval) out.push('jitOff')
  if (saved.sso_require_mfa_evidence && !next.sso_require_mfa_evidence) out.push('ssoMfaProofOff')
  if (next.sso_exceptions.some((e) => !saved.sso_exceptions.some((s) => s.user_id === e.user_id))) {
    out.push('ssoExceptionAdded')
  }
  if (saved.invitees !== 'any' && next.invitees === 'any') out.push('inviteesAny')
  if (saved.external_access_end_required && !next.external_access_end_required) {
    out.push('externalEndOff')
  }
  if (stepUpLooser(saved.step_up, next.step_up)) out.push('stepUpLooser')
  return out
}

const LOOSENING_TEXT: Record<string, string> = {
  mfaOff: 'Two-factor authentication is no longer required for everyone.',
  mfaAdminsOff: 'Owners and administrators no longer need two-factor authentication.',
  ipEmptied: 'The IP allowlist is emptied: every network may connect.',
  ipWidened: 'The IP allowlist allows more networks.',
  domainsWidened: 'More email domains may join.',
  personalLooser: 'Personal accounts get more access.',
  jitOff: 'New SSO members get access without approval.',
  ssoMfaProofOff: 'Your identity provider no longer has to confirm a second factor.',
  ssoExceptionAdded: 'More members may sign in without single sign-on.',
  inviteesAny: 'Anyone may be invited.',
  externalEndOff: 'External members no longer need an end date.',
  stepUpLooser: 'People are asked to confirm their identity less often.',
}

/** The name of each field in the save bar's "What changes" list: i18n key, English. */
const FIELD_LABEL: Record<SignInField, [string, string]> = {
  mfa_required: ['org.auth.mfa.all', 'Require for everyone'],
  mfa_required_for_admins: ['org.auth.mfa.admins', 'Require for owners and administrators'],
  sso_require_mfa_evidence: ['org.auth.mfa.ssoProof', 'SSO must prove two-factor'],
  step_up: ['org.auth.stepUp.title', 'Re-verification'],
  email_verification_mode: ['org.auth.email.title', 'Email verification'],
  ip_whitelist: ['org.access.ip', 'IP allowlist'],
  invitees: ['org.invitePolicy.title', 'Who can be invited'],
  allowed_domains: ['org.access.domains', 'Allowed email domains'],
  external_access_end_required: [
    'org.invitePolicy.endRequired',
    'Require an end of access for people outside',
  ],
  jit_requires_approval: ['org.auth.jit', 'Approve new SSO members'],
  personal_accounts: ['org.personal.title', 'Personal accounts'],
  sso_exceptions: ['org.personal.exceptions', 'SSO exceptions'],
}

/**
 * Settings › Sign-in: how people sign in to the organization (Sign-in tab)
 * and who may join it (Joining tab). Each tab has its own save bar and saves
 * only its own fields, with the other tab's saved values, in the one request
 * the API takes (PATCH /tenants/{tenant}/settings/security: owner only,
 * recent sign-in). The API refuses an IP allowlist that would lock the saver
 * out. Changes that weaken protection are listed and confirmed first. The
 * Joining tab also holds the verified domains, trusted organizations and the
 * SSO changes waiting for an owner, each with its own reads and saves.
 */
export function SignInSettings() {
  const { t } = useTranslation()
  const router = useRouter()
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id
  const { isOwner, isAtLeast, isLoading: permissionsLoading } = usePermissions()
  // Owner only on the backend (RequireTeamOwner + step-up).
  const canEdit = useCanMutate('PATCH /api/v1/tenants/{tenant}/settings/security')
  const { settings, isLoading, isError, error, mutate } = useTenantSettings(tenantId)
  const { updateSecuritySettings, isUpdating } = useUpdateSecuritySettings(tenantId)

  const [tabParam, setTabParam] = useUrlFilter('tab', 'sign-in')
  const [hashTab, setHashTab] = useState<SignInTab | null>(null)
  const tab: SignInTab =
    tabParam === 'joining' || TAB_SECTION[tabParam] ? 'joining' : (hashTab ?? 'sign-in')
  const ready = !isLoading && !isError

  const saved = useMemo(() => signInFormFrom(settings), [settings])
  const [form, setForm] = useState<SignInForm>(saved)
  const [ipError, setIpError] = useState<string | null>(null)
  const [confirm, setConfirm] = useState<{ tab: SignInTab; keys: string[] } | null>(null)
  const [saveError, setSaveError] = useState<SignInTab | null>(null)
  const [leaveTo, setLeaveTo] = useState<string | null>(null)

  // When the saved values change (load, a save, a refresh) keep what the user
  // edited and take the new saved value for every field they did not touch:
  // saving one tab never drops the other tab's unsaved changes.
  const prevSaved = useRef(saved)
  useEffect(() => {
    const before = prevSaved.current
    prevSaved.current = saved
    setForm((f) => withFields(saved, f, changedOf(before, f, SIGN_IN_FIELDS)))
  }, [saved])

  // A link to a setting on the other tab (settings search, the security
  // overview, a redirect from an old page) opens that tab;
  // useSettingsAnchorHighlight then scrolls to it. ?tab=domains and the like
  // open the Joining tab at that section.
  useEffect(() => {
    const follow = () =>
      window.setTimeout(() => {
        const id = decodeURIComponent(window.location.hash.slice(1))
        const target: SignInTab | null = JOINING_ANCHORS.has(id)
          ? 'joining'
          : SIGN_IN_ANCHORS.has(id)
            ? 'sign-in'
            : null
        if (!target) return
        setHashTab(target)
        if (new URLSearchParams(window.location.search).has('tab')) setTabParam('')
      }, 0)
    follow()
    const onClick = (e: MouseEvent) => {
      if ((e.target as Element | null)?.closest?.('a[href*="#"]')) follow()
    }
    document.addEventListener('click', onClick)
    window.addEventListener('hashchange', follow)
    window.addEventListener(SETTINGS_ANCHOR_EVENT, follow)
    return () => {
      document.removeEventListener('click', onClick)
      window.removeEventListener('hashchange', follow)
      window.removeEventListener(SETTINGS_ANCHOR_EVENT, follow)
    }
  }, [setTabParam])
  const section = TAB_SECTION[tabParam]
  useEffect(() => {
    if (ready && section) document.getElementById(section)?.scrollIntoView?.({ block: 'start' })
  }, [ready, section])

  const changed: Record<SignInTab, SignInField[]> = {
    'sign-in': changedOf(saved, form, TAB_FIELDS['sign-in']),
    joining: changedOf(saved, form, TAB_FIELDS.joining),
  }
  const other: SignInTab = tab === 'sign-in' ? 'joining' : 'sign-in'
  const dirty = changed[tab].length > 0
  // The other tab's unsaved changes: its bar is not shown, so the page asks
  // before leaving for them itself.
  const otherDirty = changed[other].length > 0
  useUnsavedChangesGuard(otherDirty && !dirty, setLeaveTo)

  const patchForm = (p: Partial<SignInForm>) => setForm((f) => ({ ...f, ...p }))

  const discard = useCallback(
    (which: SignInTab) => {
      setForm((f) => withFields(f, saved, TAB_FIELDS[which]))
      if (which === 'sign-in') setIpError(null)
      setSaveError(null)
    },
    [saved]
  )

  const doSave = async (which: SignInTab) => {
    setConfirm(null)
    if (which === 'sign-in') setIpError(null)
    setSaveError(null)
    const next = withFields(saved, form, TAB_FIELDS[which])
    try {
      const result = await updateSecuritySettings({
        mfa_required: next.mfa_required,
        mfa_required_for_admins: next.mfa_required_for_admins,
        ip_whitelist: parseLines(next.ip_whitelist),
        allowed_domains: parseLines(next.allowed_domains),
        email_verification_mode: next.email_verification_mode,
        personal_accounts: next.personal_accounts,
        invitees: next.invitees,
        external_access_end_required: next.external_access_end_required,
        sso_exceptions: next.sso_exceptions,
        jit_requires_approval: next.jit_requires_approval,
        sso_require_mfa_evidence: next.sso_require_mfa_evidence,
        step_up: next.step_up,
      })
      if (result) await mutate(result, { revalidate: false })
      toast.success(t('org.auth.saved', 'Sign-in settings saved'))
    } catch (err) {
      // The API refuses an allowlist that would lock the saver out: show it
      // next to the field, not only in a toast.
      if (isIpLockoutError(err)) setIpError(err.message)
      setSaveError(which)
      toast.error(
        getErrorMessage(err, t('org.auth.saveFailed', 'Could not save the sign-in settings'))
      )
    }
  }

  const handleSave = (which: SignInTab) => {
    const loosened = looseningsOf(saved, withFields(saved, form, TAB_FIELDS[which]))
    if (loosened.length > 0) setConfirm({ tab: which, keys: loosened })
    else void doSave(which)
  }

  const title = t('org.auth.title', 'Sign-in')
  const description = t(
    'org.auth.desc',
    'How people sign in to this organization, and who may join.'
  )
  if (!ready) {
    return (
      <SettingsPage
        title={title}
        description={description}
        state={isLoading ? 'loading' : 'error'}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }

  const disabled = !canEdit
  const platformFloor = settings?.security?.platform_mfa_floor ?? 'none'
  const floorEveryone = platformFloor === 'everyone'
  const floorAdmins = platformFloor === 'admins' || floorEveryone
  const lastChanged = (which: SignInTab) => (
    <LastChanged resourceType="tenant" resourceId={tenantId} fields={TAB_FIELDS[which]} />
  )
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
  ]
  const unsavedMark = (which: SignInTab) =>
    which !== tab && changed[which].length > 0 ? (
      <span className="text-cap text-muted-foreground">{t('org.auth.tabUnsaved', 'unsaved')}</span>
    ) : null

  const saveBar = (which: SignInTab) => (
    <SettingsSaveBar
      dirty={changed[which].length > 0}
      saving={isUpdating}
      changes={changed[which].map((k) => t(FIELD_LABEL[k][0], FIELD_LABEL[k][1]))}
      error={
        saveError === which
          ? t('settings.saveBar.failed', "Couldn't save. Your changes are kept.")
          : undefined
      }
      onSave={() => handleSave(which)}
      onDiscard={() => discard(which)}
    />
  )

  return (
    <SettingsPage
      title={title}
      description={description}
      readOnly={
        disabled
          ? t('org.auth.ownerOnly', 'Only the organization owner can change these settings.')
          : undefined
      }
    >
      <Tabs
        value={tab}
        onValueChange={(v) => {
          setHashTab(null)
          setTabParam(v === 'sign-in' ? '' : v)
        }}
        className="gap-section"
      >
        <TabsList aria-label={t('org.auth.tabs.label', 'Sign-in settings')}>
          <TabsTrigger value="sign-in">
            {t('org.auth.tabs.signIn', 'Sign-in')}
            {unsavedMark('sign-in')}
          </TabsTrigger>
          <TabsTrigger value="joining">
            {t('org.auth.tabs.joining', 'Joining')}
            {unsavedMark('joining')}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="sign-in" className="flex min-w-0 flex-col gap-section">
          <SettingsSection
            framed
            id="two-factor"
            title={t('org.auth.mfa.title', 'Two-factor authentication')}
            description={t(
              'org.auth.mfa.desc',
              "Members who sign in through SSO use your identity provider's two-factor settings."
            )}
            meta={lastChanged('sign-in')}
          >
            {floorAdmins && (
              <SettingsBlock>
                <p className="text-dense text-muted-foreground" data-testid="mfa-platform-floor">
                  {floorEveryone
                    ? t(
                        'org.auth.mfa.platformFloorEveryone',
                        'The platform requires it for every member.'
                      )
                    : t(
                        'org.auth.mfa.platformFloorAdmins',
                        'The platform requires it for owners, administrators and members with a privileged role. You can require it for everyone.'
                      )}
                </p>
              </SettingsBlock>
            )}
            <SettingsSwitchRow
              id="tenant-mfa-required"
              label={t('org.auth.mfa.all', 'Require for everyone')}
              hint={t(
                'org.auth.mfa.allHint',
                'Members who sign in with a password set up an authenticator app at their next sign-in.'
              )}
              checked={form.mfa_required}
              onCheckedChange={(v) => patchForm({ mfa_required: v })}
              disabled={disabled || floorEveryone}
            />
            <SettingsSwitchRow
              id="tenant-mfa-admins"
              label={t('org.auth.mfa.admins', 'Require for owners and administrators')}
              hint={t(
                'org.auth.mfa.adminsHint',
                'Owners, administrators and members with a privileged role. On for new organizations.'
              )}
              checked={form.mfa_required || form.mfa_required_for_admins}
              onCheckedChange={(v) => patchForm({ mfa_required_for_admins: v })}
              disabled={disabled || form.mfa_required || floorAdmins}
            />
            <SettingsSwitchRow
              id="tenant-sso-mfa-proof"
              label={t('org.auth.mfa.ssoProof', 'SSO must prove two-factor')}
              hint={t(
                'org.auth.mfa.ssoProofHint',
                'An SSO sign-in counts only when your identity provider confirms a second factor. Turn that on in the provider first.'
              )}
              checked={form.sso_require_mfa_evidence}
              onCheckedChange={(v) => patchForm({ sso_require_mfa_evidence: v })}
              disabled={disabled}
            />
          </SettingsSection>

          <StepUpPolicyCard
            policy={form.step_up}
            onChange={(p) => patchForm({ step_up: p })}
            disabled={disabled}
          />

          <SettingsSection
            framed
            id="new-accounts"
            title={t('org.auth.newAccounts.title', 'New accounts')}
            description={t(
              'org.auth.newAccounts.desc',
              'How a new account proves its email address.'
            )}
          >
            <SettingsRow
              id="email-verification"
              wide
              label={
                <label htmlFor="email-verification-mode">
                  {t('org.auth.email.title', 'Email verification')}
                </label>
              }
              hint={t(
                'org.auth.email.desc',
                'Whether new accounts must verify their email address before signing in.'
              )}
              hintId="email-verification-desc"
            >
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
                  className="w-full"
                >
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {emailModes.map((m) => (
                    <SelectItem key={m.value} value={m.value}>
                      <div className="flex flex-col items-start">
                        <span className="font-medium">{m.label}</span>
                        <span className="text-cap text-muted-foreground">{m.hint}</span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </SettingsRow>
          </SettingsSection>

          <NetworkRestrictionSection
            ipAllowlist={form.ip_whitelist}
            onIpAllowlistChange={(v) => {
              setIpError(null)
              patchForm({ ip_whitelist: v })
            }}
            currentIp={settings?.security?.current_ip}
            ipAllowlistError={ipError}
            disabled={disabled}
          />

          <SsoManagedNotice />

          <p className="flex items-center gap-2 text-dense text-muted-foreground">
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

          {tab === 'sign-in' && saveBar('sign-in')}
        </TabsContent>

        <TabsContent value="joining" className="flex min-w-0 flex-col gap-section">
          {tab === 'joining' && isOwner() && <SsoChangesBanner />}

          <SettingsSection
            framed
            id="who-may-join"
            title={t('org.auth.join.title', 'Who may join')}
            description={t(
              'org.auth.join.desc',
              'Applies when an invitation is sent, when it is accepted and when someone signs in through SSO for the first time.'
            )}
            meta={lastChanged('joining')}
          >
            <InvitationPolicyCard
              invitees={form.invitees}
              onInviteesChange={(p) => patchForm({ invitees: p })}
              endRequired={form.external_access_end_required}
              onEndRequiredChange={(v) => patchForm({ external_access_end_required: v })}
              hasAllowedDomains={parseLines(form.allowed_domains).length > 0}
              disabled={disabled}
            />
            <AllowedDomainsBlock
              allowedDomains={form.allowed_domains}
              onAllowedDomainsChange={(v) => patchForm({ allowed_domains: v })}
              disabled={disabled}
            />
            <div id="sso-member-approval">
              <SettingsSwitchRow
                id="tenant-jit-approval"
                label={t('org.auth.jit', 'Approve new SSO members')}
                hint={t(
                  'org.auth.jitHint',
                  'First-time SSO users wait without access until an administrator approves them in Members.'
                )}
                checked={form.jit_requires_approval}
                onCheckedChange={(v) => patchForm({ jit_requires_approval: v })}
                disabled={disabled}
              />
            </div>
          </SettingsSection>

          <PersonalAccountsCard
            tenantSlug={tenantId}
            policy={form.personal_accounts}
            onPolicyChange={(p) => patchForm({ personal_accounts: p })}
            exceptions={form.sso_exceptions}
            onExceptionsChange={(e) => patchForm({ sso_exceptions: e })}
            ssoEnforced={!!settings?.security?.sso_enforced}
            disabled={disabled}
          />

          {/* Lists with their own reads and saves: loaded only on this tab. */}
          {tab === 'joining' && !permissionsLoading && (
            <>
              <SettingsSection
                framed
                id="domains"
                title={t('settings.domains.title', 'Verified domains')}
                description={t(
                  'settings.domains.desc',
                  'What your verified single sign-on domains do to accounts on them.'
                )}
              >
                <DomainSignupPolicies canRead={isAtLeast('admin')} isOwner={isOwner()} />
              </SettingsSection>

              <TrustedOrganizations canRead={isAtLeast('admin')} isOwner={isOwner()} />

              <SettingsSection
                framed
                id="sso-approvals"
                title={t('settings.ssoApprovals.title', 'SSO changes')}
                description={t(
                  'settings.ssoApprovals.description',
                  'Sign-in changes proposed by the platform administrator. None takes effect until an owner approves it.'
                )}
              >
                <SSOChangeApprovals canDecide={isOwner()} />
              </SettingsSection>
            </>
          )}

          {tab === 'joining' && saveBar('joining')}
        </TabsContent>
      </Tabs>

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
              {(confirm?.keys ?? []).map((k) => (
                <li key={k}>{t(`org.auth.loosen.${k}`, LOOSENING_TEXT[k] ?? k)}</li>
              ))}
            </ul>
          </div>
        }
        confirmText={t('org.auth.loosen.confirm', 'Save anyway')}
        isLoading={isUpdating}
        handleConfirm={() => confirm && void doSave(confirm.tab)}
      />

      {/* Leaving with unsaved changes on the tab that is not shown. */}
      <ConfirmDialog
        open={leaveTo !== null}
        onOpenChange={(open) => !open && setLeaveTo(null)}
        destructive
        title={t('settings.saveBar.leaveTitle', 'Leave without saving?')}
        desc={t(
          'settings.saveBar.leaveDesc',
          'Your changes on this page are not saved. If you leave, they are lost.'
        )}
        cancelBtnText={t('settings.saveBar.stay', 'Stay on this page')}
        confirmText={t('settings.saveBar.leave', 'Leave and discard')}
        handleConfirm={() => {
          const to = leaveTo
          setLeaveTo(null)
          discard(other)
          if (to) router.push(to)
        }}
      />
    </SettingsPage>
  )
}

/**
 * "N SSO changes wait for your decision" above the Joining tab, for owners
 * (the only ones who may decide): the same read as the list below it.
 */
function SsoChangesBanner() {
  const { t } = useTranslation()
  const { data } = useSSOChanges({ enabled: true })
  const count = data?.changes?.length ?? 0
  if (count === 0) return null
  return (
    <Alert data-testid="sso-changes-banner">
      <AlertDescription className="flex flex-wrap items-center justify-between gap-2">
        <span>
          {t(
            'org.auth.ssoChangesWaiting',
            '{count, plural, one {# SSO change waits for your decision.} other {# SSO changes wait for your decision.}}',
            { count }
          )}
        </span>
        <Button
          size="sm"
          variant="outline"
          onClick={() =>
            document.getElementById('sso-approvals')?.scrollIntoView({ block: 'start' })
          }
        >
          {t('org.auth.ssoChangesReview', 'Review')}
        </Button>
      </AlertDescription>
    </Alert>
  )
}
