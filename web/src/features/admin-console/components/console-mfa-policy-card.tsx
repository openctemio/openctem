'use client'

import { useId, useState } from 'react'
import { Fingerprint } from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState } from '@/features/shared'
import { AdminApiError } from '../api/admin-client'
import { saveConsoleMfaPolicy, useConsoleMfaPolicy } from '../api/use-console-factors'

/**
 * System > Admin sign-in: "Require security keys" (RFC-078 §7.2). Super admin
 * + step-up; the API refuses to turn it on unless the console has a relying
 * party and the actor holds two keys and unused recovery codes, so the person
 * turning it on can always sign in. The switch is a convenience: the API is
 * the authority.
 */
export function ConsoleMfaPolicyCard() {
  const { t } = useTranslation()
  const switchId = useId()
  const { data, error, isLoading, mutate } = useConsoleMfaPolicy()
  const [pending, setPending] = useState<boolean | null>(null)
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<'not_compliant' | 'conflict' | string | null>(null)

  if (error) {
    return (
      <ErrorState
        title={t('admin.mfaPolicy.title', 'Require security keys')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) return <Skeleton className="h-40 w-full" />

  const save = async () => {
    if (pending === null) return
    setBusy(true)
    setProblem(null)
    try {
      await saveConsoleMfaPolicy({ require_webauthn: pending, version: data.version })
      toast.success(
        pending
          ? t('admin.mfaPolicy.onToast', 'Security keys are now required')
          : t('admin.mfaPolicy.offToast', 'Security keys are no longer required')
      )
      setPending(null)
      await mutate()
    } catch (err) {
      setPending(null)
      if (err instanceof AdminApiError && err.code === 'MFA_POLICY_ACTOR_NOT_COMPLIANT') {
        setProblem('not_compliant')
      } else if (err instanceof AdminApiError && err.status === 409) {
        setProblem('conflict')
        await mutate()
      } else if (err instanceof AdminApiError && err.code === 'ADMIN_STEP_UP_REQUIRED') {
        setProblem(
          t('admin.mfaPolicy.stepUpCancelled', 'Nothing changed: the action was not confirmed.')
        )
      } else {
        setProblem(
          err instanceof Error && err.message
            ? err.message
            : t('admin.mfaPolicy.failed', 'The policy could not be saved.')
        )
      }
    } finally {
      setBusy(false)
    }
  }

  const problemText =
    problem === 'not_compliant'
      ? t(
          'admin.mfaPolicy.notCompliant',
          'Register at least two security keys and generate recovery codes for your own account first, so you can always sign in.'
        )
      : problem === 'conflict'
        ? t(
            'admin.mfaPolicy.conflict',
            'Someone changed this policy since you opened the page. It was reloaded: check it and try again.'
          )
        : problem

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Fingerprint className="size-4 text-muted-foreground" />
          {t('admin.mfaPolicy.title', 'Require security keys')}
        </CardTitle>
        <CardDescription>
          {t(
            'admin.mfaPolicy.description',
            'Administrators who hold a security key or passkey must use it: the authenticator app is refused at sign-in and for sensitive actions, since a phishing site can relay its codes but not a key.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!data.webauthn_enabled && (
          <Alert>
            <AlertDescription>
              {t(
                'admin.mfaPolicy.notConfigured',
                'Unavailable: security keys need the console address (ADMIN_PUBLIC_URL) to be set on the API.'
              )}
            </AlertDescription>
          </Alert>
        )}
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1">
            <Label htmlFor={switchId}>{t('admin.mfaPolicy.switch', 'Require security keys')}</Label>
            <p className="text-xs text-muted-foreground">
              {data.require_webauthn
                ? t('admin.mfaPolicy.stateOn', 'On')
                : t('admin.mfaPolicy.stateOff', 'Off')}
            </p>
          </div>
          <Switch
            id={switchId}
            checked={data.require_webauthn}
            disabled={busy || (!data.webauthn_enabled && !data.require_webauthn)}
            onCheckedChange={(v) => {
              setProblem(null)
              setPending(v)
            }}
          />
        </div>
        <ul className="list-disc space-y-1 ps-5 text-sm text-muted-foreground">
          <li>
            {t(
              'admin.mfaPolicy.ruleActor',
              'To turn it on you must hold at least two security keys and unused recovery codes yourself.'
            )}{' '}
            <Link href="/admin/security/keys" className="underline underline-offset-4">
              {t('admin.mfaPolicy.manageKeys', 'My security keys')}
            </Link>
          </li>
          <li>
            {t(
              'admin.mfaPolicy.ruleOthers',
              'Other administrators are not locked out: they are asked to register keys and recovery codes before the rest of the console opens.'
            )}
          </li>
          <li>
            {t(
              'admin.mfaPolicy.ruleFloor',
              'Nobody can remove a key below two; recovery codes still work at sign-in.'
            )}
          </li>
          <li>
            {t(
              'admin.mfaPolicy.ruleBreakGlass',
              'Break-glass (emergency) administrators keep the authenticator app.'
            )}
          </li>
        </ul>
        {problemText && (
          <Alert variant="destructive">
            <AlertDescription>{problemText}</AlertDescription>
          </Alert>
        )}
      </CardContent>
      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(open) => !open && !busy && setPending(null)}
        title={
          pending
            ? t('admin.mfaPolicy.confirmOnTitle', 'Require security keys?')
            : t('admin.mfaPolicy.confirmOffTitle', 'Stop requiring security keys?')
        }
        desc={
          pending
            ? t(
                'admin.mfaPolicy.confirmOnDesc',
                'Administrators with a key can no longer use the authenticator app; the others are held on enrollment until they register keys. You confirm it is you first.'
              )
            : t(
                'admin.mfaPolicy.confirmOffDesc',
                'Administrators may use the authenticator app again. You confirm it is you first.'
              )
        }
        destructive={pending === false}
        confirmText={t('admin.mfaPolicy.confirm', 'Confirm')}
        isLoading={busy}
        handleConfirm={() => void save()}
      />
    </Card>
  )
}
