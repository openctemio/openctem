'use client'

/**
 * Scan assets now with a Tenable.sc connector (POST /integrations/{id}/scans/run):
 * "Scan with Tenable.sc" on an asset and "Rescan with Tenable.sc" on a
 * finding. Shown only to callers with scans:write who can list the
 * connectors (integrations:read) when the organization has one; with several
 * connectors the caller picks one. The API is the authority: it scans only
 * assets of the caller's data scope and runs every scan gate.
 */

import { useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import { toast } from 'sonner'
import { ChevronDown, Loader2, Radar } from 'lucide-react'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  useConnectorScanNowApi,
  useSecurityIntegrationsApi,
} from '@/features/integrations/api/use-integrations-api'
import { TENABLE_CONNECTOR_ENABLED } from '@/features/integrations/config/feature-gates'
import { tenableSCConnectors } from '@/features/integrations/lib/tenable-sc'
import type { Integration } from '@/features/integrations/types/integration.types'
import { runHref } from '@/features/scans/lib/run-display'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions, Permission } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'

/** The connectors the caller may scan with: enabled Tenable.sc connectors. */
export function useScanNowConnectors(): Integration[] {
  const { can } = usePermissions()
  const allowed =
    TENABLE_CONNECTOR_ENABLED && can(Permission.ScansWrite) && can(Permission.IntegrationsRead)
  const { data } = useSecurityIntegrationsApi(allowed)
  return useMemo(
    () => (allowed ? tenableSCConnectors(data?.data).filter((i) => i.status !== 'disabled') : []),
    [allowed, data?.data]
  )
}

export interface TenableScanNowButtonProps {
  assetIds: string[]
  /** The button's text (the page's own namespace). */
  label: string
  /** Its tooltip. */
  title?: string
  variant?: 'default' | 'outline'
  className?: string
  onStarted?: (runId: string) => void
}

export function TenableScanNowButton({
  assetIds,
  label,
  title,
  variant = 'outline',
  className,
  onStarted,
}: TenableScanNowButtonProps) {
  const { t } = useTranslation()
  const router = useRouter()
  const connectors = useScanNowConnectors()
  const { trigger, isMutating } = useConnectorScanNowApi()
  // A scan sends traffic to the assets now: the user confirms the connector first.
  const [pending, setPending] = useState<Integration | null>(null)

  if (connectors.length === 0 || assetIds.length === 0) return null

  const start = async (integration: Integration) => {
    try {
      const run = await trigger({ integrationId: integration.id, assetIds })
      toast.success(t('tenableSc.scanNow.started', 'Tenable.sc scan started'), {
        description: t(
          'tenableSc.scanNow.startedDesc',
          'Scanning with {name}. Results arrive when Tenable.sc finishes and the connector imports them.',
          { name: integration.name }
        ),
        action: run?.id
          ? {
              label: t('tenableSc.scanNow.viewRun', 'View run'),
              onClick: () => router.push(runHref(run.id)),
            }
          : undefined,
      })
      if (run?.id) onStarted?.(run.id)
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('tenableSc.scanNow.failed', 'Could not start the Tenable.sc scan'))
      )
    }
  }

  const icon = isMutating ? (
    <Loader2 className="me-1.5 h-3.5 w-3.5 animate-spin" aria-hidden />
  ) : (
    <Radar className="me-1.5 h-3.5 w-3.5" aria-hidden />
  )

  const count = assetIds.length
  const dialog = (
    <ConfirmDialog
      open={pending !== null}
      onOpenChange={(open) => !open && setPending(null)}
      title={
        count === 1
          ? t('confirm.tenableScan.titleOne', undefined, { name: pending?.name ?? '' })
          : t('confirm.tenableScan.title', undefined, { count, name: pending?.name ?? '' })
      }
      desc={t('confirm.tenableScan.desc')}
      confirmText={
        count === 1
          ? t('confirm.tenableScan.btnOne')
          : t('confirm.tenableScan.btn', undefined, { count })
      }
      handleConfirm={async () => {
        const integration = pending
        setPending(null)
        if (integration) await start(integration)
      }}
    />
  )

  if (connectors.length === 1) {
    return (
      <>
        <Button
          size="sm"
          variant={variant}
          className={className}
          title={title}
          disabled={isMutating}
          onClick={() => setPending(connectors[0])}
        >
          {icon}
          {label}
        </Button>
        {dialog}
      </>
    )
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            size="sm"
            variant={variant}
            className={className}
            title={title}
            disabled={isMutating}
          >
            {icon}
            {label}
            <ChevronDown className="ms-1 h-3.5 w-3.5" aria-hidden />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuLabel>
            {t('tenableSc.scanNow.pickConnector', 'Scan with connector')}
          </DropdownMenuLabel>
          {connectors.map((c) => (
            <DropdownMenuItem key={c.id} onSelect={() => setPending(c)}>
              {c.name}
            </DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
      {dialog}
    </>
  )
}
