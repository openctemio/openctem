'use client'

/**
 * "OIDC required for CI" (api RFC-051): when on, a CI sensor's API key is
 * refused and CI jobs must use their provider's OIDC identity. On for new
 * organizations; an existing organization sees a banner until it opts in.
 */

import { toast } from 'sonner'
import { ShieldAlert, ShieldCheck } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useCISettings, useSaveCISettings } from '../api/use-ci'

export function CIRequireOIDC({ canWrite }: { canWrite: boolean }) {
  const { data, error, mutate } = useCISettings()
  const { trigger, isMutating } = useSaveCISettings()
  if (error || !data) return null
  const required = !!data.require_oidc

  const change = async (next: boolean) => {
    try {
      const saved = await trigger({ require_oidc: next })
      await mutate(saved, { revalidate: false })
      toast.success(next ? 'CI sensor keys are refused now' : 'CI sensor keys are accepted again')
    } catch {
      toast.error('The CI setting was not saved')
    }
  }

  const toggle = (
    <div className="flex items-center gap-2">
      <Switch
        id="ci-require-oidc"
        checked={required}
        disabled={!canWrite || isMutating}
        onCheckedChange={change}
      />
      <Label htmlFor="ci-require-oidc" className="font-normal">
        Require OIDC for CI
      </Label>
    </div>
  )

  if (required) {
    return (
      <Alert>
        <ShieldCheck />
        <AlertTitle>CI jobs must use their OIDC identity</AlertTitle>
        <AlertDescription className="space-y-2">
          <p>
            Results sent by a CI sensor with an API key are refused. Pipelines authenticate with the
            token their CI provider issues for the job, checked against the trust configurations
            below.
          </p>
          {toggle}
        </AlertDescription>
      </Alert>
    )
  }
  return (
    <Alert variant="destructive" data-testid="ci-require-oidc-banner">
      <ShieldAlert />
      <AlertTitle>CI sensor API keys are still accepted</AlertTitle>
      <AlertDescription className="space-y-2">
        <p>
          A stored CI key never expires with the job and works from anywhere it leaks to. Move your
          pipelines to OIDC (add trust below, set OPENCTEM_TENANT_ID in the pipeline), then require
          it.
        </p>
        {toggle}
      </AlertDescription>
    </Alert>
  )
}
