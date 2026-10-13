'use client'

import { useState } from 'react'
import { Loader2, Sparkles } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { put } from '@/lib/api/client'
import { scanEndpoints } from '@/lib/api/endpoints'
import { getErrorMessage } from '@/lib/api/error-handler'
import type { ScanConfig } from '@/lib/api/scan-types'
import { useScanWorkflow } from '@/lib/api/scan-workflow-hooks'
import { Can, Permission } from '@/lib/permissions'
import { apiTargetOptions, hasCidrTarget } from '../lib/dynamic-targets'
import { canFindLiveHosts, effectiveCidrMode } from '../lib/liveness'

/**
 * A saved scan that sweeps its address ranges while its scan could find the
 * live hosts first: a non-blocking hint with a one-click switch (scans write).
 * The scan is never switched without it (RFC-088 decision A1).
 */
export function LivenessHint({ config, onChanged }: { config: ScanConfig; onChanged: () => void }) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const isWorkflow = config.scan_type === 'workflow'
  const ranges = hasCidrTarget(config.targets ?? [])
  const sweeping = effectiveCidrMode(config.target_options?.cidr_mode, true) === 'sweep'
  const { data: workflow } = useScanWorkflow(
    ranges && sweeping && isWorkflow && config.scan_workflow_id ? config.scan_workflow_id : null,
    { revalidateOnFocus: false }
  )
  if (!ranges || !sweeping) return null
  if (canFindLiveHosts(isWorkflow ? 'workflow' : 'single', workflow) !== true) return null

  const switchMode = async () => {
    setBusy(true)
    try {
      await put(scanEndpoints.update(config.id), {
        target_options: {
          ...(apiTargetOptions(config.target_options) ?? {}),
          cidr_mode: 'liveness',
        },
      })
      toast.success(t('scans.liveness.switched'))
      onChanged()
    } catch (err) {
      toast.error(getErrorMessage(err, t('scans.liveness.switchFailed')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      role="note"
      data-testid="liveness-hint"
      className="flex flex-wrap items-center gap-3 rounded-lg border border-info/40 bg-info/10 px-4 py-3"
    >
      <Sparkles className="h-4 w-4 shrink-0 text-info" aria-hidden />
      <div className="min-w-0 flex-1 text-sm">
        <p className="font-medium">{t('scans.liveness.title')}</p>
        <p className="text-xs text-muted-foreground">
          {t(isWorkflow ? 'scans.liveness.hintWorkflow' : 'scans.liveness.hintScanner')}
        </p>
      </div>
      <Can permission={Permission.ScansWrite} mode="disable">
        <Button size="sm" variant="outline" onClick={() => void switchMode()} disabled={busy}>
          {busy && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
          {t('scans.liveness.switch')}
        </Button>
      </Can>
    </div>
  )
}
