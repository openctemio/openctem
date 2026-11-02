'use client'

/**
 * "OIDC required for CI" (api RFC-051): when on, a CI sensor's API key is
 * refused and CI jobs must use their provider's OIDC identity. On for new
 * organizations; an existing organization sees a banner until it opts in.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { ShieldAlert, ShieldCheck } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useCISettings, useSaveCISettings } from '../api/use-ci'
import { useTranslation } from '@/context/i18n-provider'

export function CIRequireOIDC({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const { data, error, mutate } = useCISettings()
  const { trigger, isMutating } = useSaveCISettings()
  // Accepting CI sensor keys again weakens CI authentication: ask first.
  const [askLoosen, setAskLoosen] = useState(false)
  if (error || !data) return null
  const required = !!data.require_oidc

  const change = async (next: boolean) => {
    try {
      const saved = await trigger({ require_oidc: next })
      await mutate(saved, { revalidate: false })
      toast.success(
        next
          ? t('scans.ci.oidc.refusedNow', 'CI sensor keys are refused now')
          : t('scans.ci.oidc.acceptedAgain', 'CI sensor keys are accepted again')
      )
    } catch {
      toast.error(t('scans.ci.oidc.notSaved', 'The CI setting was not saved'))
    }
  }

  const toggle = (
    <div className="flex items-center gap-2">
      <Switch
        id="ci-require-oidc"
        checked={required}
        disabled={!canWrite || isMutating}
        onCheckedChange={(next) => (next ? void change(true) : setAskLoosen(true))}
      />
      <Label htmlFor="ci-require-oidc" className="font-normal">
        {t('scans.ci.oidc.toggle', 'Require OIDC for CI')}
      </Label>
    </div>
  )

  const dialog = (
    <ConfirmDialog
      open={askLoosen}
      onOpenChange={setAskLoosen}
      destructive
      title={t('confirm.ciOidc.title')}
      desc={t('confirm.ciOidc.desc')}
      confirmText={t('confirm.ciOidc.btn')}
      handleConfirm={async () => {
        setAskLoosen(false)
        await change(false)
      }}
    />
  )

  if (required) {
    // The safe state is one quiet line: it only needs attention when off.
    return (
      <>
        {dialog}
        <div
          className="flex flex-col gap-2 rounded-lg border p-3 text-sm sm:flex-row sm:items-center sm:justify-between"
          data-testid="ci-require-oidc-on"
        >
          <p className="flex min-w-0 items-start gap-2">
            <ShieldCheck className="mt-0.5 size-4 shrink-0 text-success" aria-hidden />
            <span>
              <span className="font-medium">
                {t('scans.ci.oidc.requiredTitle', 'CI jobs must use their OIDC identity')}
              </span>{' '}
              <span className="text-muted-foreground">
                {t('scans.ci.oidc.requiredShort', 'CI sensor API keys are refused.')}
              </span>
            </span>
          </p>
          {toggle}
        </div>
      </>
    )
  }
  return (
    <>
      {dialog}
      <Alert variant="destructive" data-testid="ci-require-oidc-banner">
        <ShieldAlert />
        <AlertTitle>
          {t('scans.ci.oidc.acceptedTitle', 'CI sensor API keys are still accepted')}
        </AlertTitle>
        <AlertDescription className="space-y-2">
          <p>
            {t(
              'scans.ci.oidc.acceptedBody',
              'A stored CI key never expires with the job and works from anywhere it leaks to. Move your pipelines to OIDC (add trust below, set OPENCTEM_TENANT_ID in the pipeline), then require it.'
            )}
          </p>
          {toggle}
        </AlertDescription>
      </Alert>
    </>
  )
}
