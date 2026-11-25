'use client'

import { useCallback, useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { useTranslation } from '@/context/i18n-provider'
import {
  RelativeTime,
  SettingsBlock,
  SettingsSaveBar,
  SettingsSection,
  SettingsSwitchRow,
} from '@/features/shared'
import type { SignupPolicyResponse } from '@/lib/api/generated'
import { AdminApiError } from '@console/lib/admin-api/client'
import { saveSignupPolicy } from '../api/use-signup-policy'
import { ReasonAndCodeFields, useReasonAndCode } from './step-up-code-hint'

type Mode = 'admin_only' | 'self_service'
type Accounts = 'closed' | 'domain' | 'open'

const ACCOUNTS: Accounts[] = ['closed', 'domain', 'open']
const ACCOUNTS_RANK: Record<Accounts, number> = { closed: 1, domain: 2, open: 3 }

const MODE_KEY: Record<Mode, string> = {
  admin_only: 'admin.signup.mode.adminOnly',
  self_service: 'admin.signup.mode.selfService',
}

const SOURCE_KEY: Record<string, string> = {
  environment: 'admin.signup.source.environment',
  console: 'admin.signup.source.console',
  default: 'admin.signup.source.default',
}

const DEPLOYMENT_KEY: Record<string, string> = {
  disabled: 'admin.signup.deployment.disabled',
  domain: 'admin.signup.deployment.domain',
  open: 'admin.signup.deployment.open',
}

export interface SignupPolicyFormProps {
  policy: SignupPolicyResponse
  /** False for an administrator who may read but not change the policy. */
  canEdit: boolean
  onSaved: () => void
}

/**
 * System > Sign-up: who may create an organization on this deployment. A
 * change needs a fresh authenticator code, never touches existing
 * organizations, users or sessions, and is reported to the other
 * administrators.
 */
export function SignupPolicyForm({ policy, canEdit, onSaved }: SignupPolicyFormProps) {
  const { t } = useTranslation()
  const deploymentMode = policy.deployment_mode ?? 'disabled'
  // The server configuration (SIGNUP_MODE) is the ceiling: the console can
  // never open self-service above it, and the API refuses with 409.
  const selfServiceLocked = policy.self_service_locked ?? true
  const effectiveMode = (policy.effective_mode as Mode) ?? 'admin_only'
  const storedAccounts = (policy.accounts as Accounts) ?? 'closed'
  const maxAccounts = (policy.max_accounts as Accounts) ?? 'closed'
  const [mode, setMode] = useState<Mode>((policy.mode as Mode) ?? 'admin_only')
  const [accounts, setAccounts] = useState<Accounts>(storedAccounts)
  const [requestAccess, setRequestAccess] = useState(!!policy.request_access)
  const [personalOrg, setPersonalOrg] = useState(!!policy.personal_organization)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const rc = useReasonAndCode(confirmOpen)
  const [busy, setBusy] = useState(false)
  const codeId = useId()

  // The saved values: on load, after a save and on Discard.
  const reset = useCallback(() => {
    setMode((policy.mode as Mode) ?? 'admin_only')
    setAccounts((policy.accounts as Accounts) ?? 'closed')
    setRequestAccess(!!policy.request_access)
    setPersonalOrg(!!policy.personal_organization)
  }, [policy])
  useEffect(reset, [reset])

  // Organization self-service needs open account sign-up.
  const chooseAccounts = (a: Accounts) => {
    setAccounts(a)
    if (a !== 'open') chooseMode('admin_only')
  }

  // A personal organization at sign-up needs organization self-service.
  const chooseMode = (m: Mode) => {
    setMode(m)
    if (m !== 'self_service') setPersonalOrg(false)
  }

  const dirty =
    mode !== policy.mode ||
    accounts !== storedAccounts ||
    requestAccess !== !!policy.request_access ||
    personalOrg !== !!policy.personal_organization

  const openConfirm = () => {
    setConfirmOpen(true)
  }

  const save = async () => {
    setBusy(true)
    rc.setCodeError(null)
    try {
      await saveSignupPolicy({
        mode,
        accounts,
        request_access: requestAccess,
        personal_organization: personalOrg,
        version: policy.version ?? 0,
        totp_code: rc.code.trim(),
      })
      setConfirmOpen(false)
      toast.success(t('admin.signup.saved'))
      onSaved()
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        // Wrong, reused or missing code: stay in the dialog.
        rc.refuseCode(e.message)
        return
      }
      setConfirmOpen(false)
      if (e instanceof AdminApiError && e.status === 409) {
        toast.error(
          e.code === 'SIGNUP_LOCKED_BY_DEPLOYMENT'
            ? t('admin.signup.lockedError')
            : t('admin.signup.conflict')
        )
        onSaved()
        return
      }
      toast.error(e instanceof Error ? e.message : t('admin.signup.saveFailed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <SettingsSection
        framed
        id="signup-policy"
        title={t('admin.signup.sectionTitle', 'Who can join')}
        description={t('admin.signup.desc')}
        meta={
          <>
            {t('admin.signup.current', undefined, {
              mode: t(MODE_KEY[(policy.mode as Mode) ?? 'admin_only']),
              source: t(SOURCE_KEY[policy.source ?? 'default'] ?? 'admin.signup.source.default'),
            })}
            {policy.updated_at && (
              <>
                {t('admin.signup.changed')}{' '}
                <RelativeTime date={policy.updated_at} className="text-cap" />
              </>
            )}
            {effectiveMode !== policy.mode && (
              <>
                {' '}
                {t('admin.signup.limitedByDeployment', undefined, {
                  mode: t(MODE_KEY[effectiveMode]),
                })}
              </>
            )}
          </>
        }
      >
        <SettingsBlock>
          <Alert>
            <AlertTitle>{t('admin.signup.deployment.title')}</AlertTitle>
            <AlertDescription>
              {t(DEPLOYMENT_KEY[deploymentMode] ?? 'admin.signup.deployment.disabled')}
            </AlertDescription>
          </Alert>
          {!canEdit && (
            <p className="text-cap text-muted-foreground">{t('admin.signup.readOnly')}</p>
          )}
        </SettingsBlock>

        <SettingsBlock>
          <p id={`${codeId}-acc-title`} className="text-body font-medium">
            {t('admin.signup.accounts.title')}
          </p>
          <RadioGroup
            value={accounts}
            onValueChange={(v) => chooseAccounts(v as Accounts)}
            disabled={!canEdit}
            aria-labelledby={`${codeId}-acc-title`}
          >
            {ACCOUNTS.map((a) => (
              <div key={a} className="flex items-start gap-3">
                <RadioGroupItem
                  value={a}
                  id={`${codeId}-acc-${a}`}
                  className="mt-1"
                  disabled={ACCOUNTS_RANK[a] > ACCOUNTS_RANK[maxAccounts]}
                />
                <Label htmlFor={`${codeId}-acc-${a}`} className="grid gap-1 font-normal">
                  <span className="font-medium">{t(`admin.signup.accounts.${a}`)}</span>
                  <span className="text-cap text-muted-foreground">
                    {t(`admin.signup.accounts.${a}Hint`)}
                  </span>
                </Label>
              </div>
            ))}
          </RadioGroup>
          {/* One line for every option the server configuration locks, not one under each. */}
          {ACCOUNTS.some((a) => ACCOUNTS_RANK[a] > ACCOUNTS_RANK[maxAccounts]) && (
            <p className="text-cap text-muted-foreground">{t('admin.signup.accounts.locked')}</p>
          )}
        </SettingsBlock>

        <SettingsBlock>
          <p id={`${codeId}-mode-title`} className="text-body font-medium">
            {t('admin.signup.title')}
          </p>
          <RadioGroup
            value={mode}
            onValueChange={(v) => chooseMode(v as Mode)}
            disabled={!canEdit}
            aria-labelledby={`${codeId}-mode-title`}
          >
            <div className="flex items-start gap-3">
              <RadioGroupItem value="admin_only" id={`${codeId}-admin`} className="mt-1" />
              <Label htmlFor={`${codeId}-admin`} className="grid gap-1 font-normal">
                <span className="font-medium">{t(MODE_KEY.admin_only)}</span>
                <span className="text-cap text-muted-foreground">
                  {t('admin.signup.mode.adminOnlyHint')}
                </span>
              </Label>
            </div>
            <div className="flex items-start gap-3">
              <RadioGroupItem
                value="self_service"
                id={`${codeId}-self`}
                className="mt-1"
                disabled={selfServiceLocked || accounts !== 'open'}
              />
              <Label htmlFor={`${codeId}-self`} className="grid gap-1 font-normal">
                <span className="font-medium">{t(MODE_KEY.self_service)}</span>
                <span className="text-cap text-muted-foreground">
                  {selfServiceLocked
                    ? t('admin.signup.mode.selfServiceLocked')
                    : accounts !== 'open'
                      ? t('admin.signup.mode.selfServiceNeedsOpen')
                      : t('admin.signup.mode.selfServiceHint')}
                </span>
              </Label>
            </div>
          </RadioGroup>
        </SettingsBlock>

        <SettingsSwitchRow
          id={`${codeId}-po`}
          label={t('admin.signup.personalOrg')}
          hint={
            mode === 'self_service'
              ? t('admin.signup.personalOrgHint')
              : t('admin.signup.personalOrgNeedsSelfService')
          }
          checked={personalOrg}
          onCheckedChange={setPersonalOrg}
          disabled={!canEdit || mode !== 'self_service'}
        />
        <SettingsSwitchRow
          id={`${codeId}-ra`}
          label={t('admin.signup.requestAccess')}
          hint={t('admin.signup.requestAccessHint')}
          checked={requestAccess}
          onCheckedChange={setRequestAccess}
          disabled={!canEdit}
        />
      </SettingsSection>
      {canEdit && (
        <SettingsSaveBar dirty={dirty} saving={busy} onSave={openConfirm} onDiscard={reset} />
      )}

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={(open) => {
          if (!busy) setConfirmOpen(open)
        }}
        title={t('admin.signup.confirmTitle')}
        desc={
          <div className="space-y-2">
            <p>
              {t('admin.signup.confirmSummary', undefined, {
                mode: t(MODE_KEY[mode]),
                requestAccess: requestAccess ? t('admin.signup.on') : t('admin.signup.off'),
              })}
            </p>
            {personalOrg !== !!policy.personal_organization && (
              <p>
                {t('admin.signup.confirmPersonalOrg', undefined, {
                  state: personalOrg ? t('admin.signup.on') : t('admin.signup.off'),
                })}
              </p>
            )}
            <p>
              {t('admin.signup.confirmAccounts', undefined, {
                accounts: t(`admin.signup.accounts.${accounts}`),
              })}
            </p>
            {((mode === 'self_service' && policy.mode !== 'self_service') ||
              (accounts !== 'closed' && storedAccounts === 'closed')) && (
              <p className="font-medium text-destructive">{t('admin.signup.openWarning')}</p>
            )}
            <p>{t('admin.signup.confirmBody')}</p>
          </div>
        }
        disabled={!rc.codeOk}
        isLoading={busy}
        handleConfirm={() => void save()}
        confirmText={
          busy ? (
            <>
              <Loader2 className="me-1.5 size-4 animate-spin" />
              {t('admin.signup.saving')}
            </>
          ) : (
            t('admin.signup.confirm')
          )
        }
      >
        <ReasonAndCodeFields id={codeId} state={rc} withReason={false} />
      </ConfirmDialog>
    </>
  )
}
