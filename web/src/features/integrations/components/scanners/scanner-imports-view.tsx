'use client'

/**
 * Vulnerability scanners while the Tenable connector is paused.
 *
 * The live Tenable connector and RFC-007 rolling coverage are PAUSED (owner
 * decision D-14): sensor v0.8.0 removed the Tenable runner, so a connected
 * Tenable integration would never scan. The API refuses new Tenable
 * integrations and does not run the coverage scheduler. This view offers only
 * what works, the .nessus import, and lists Tenable integrations created
 * before the pause as paused, removable rows. TenableConnectorView comes back
 * when TENABLE_CONNECTOR_ENABLED is flipped (RFC-047).
 */

import { useState } from 'react'
import { Main } from '@/components/layout'
import { PageHeader, EmptyState } from '@/features/shared'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Can, Permission } from '@/lib/permissions'
import { Clock, PauseCircle, ShieldCheck, Trash2, Upload } from 'lucide-react'
import {
  useIntegrationsApi,
  useDeleteIntegrationApi,
  invalidateIntegrationsCache,
} from '@/features/integrations/api/use-integrations-api'
import type { Integration } from '@/features/integrations/types/integration.types'
import { ImportResultsDialog, StatusBadge, getConfigString } from './shared'
import { toast } from 'sonner'

/** The .nessus import route requires both (api routes/assets.go). */
const IMPORT_PERMISSIONS = [Permission.AssetsWrite, Permission.FindingsWrite]

// ─────────────────────────────────────────────────────────
// Paused Tenable integration (created before the pause)
// ─────────────────────────────────────────────────────────

function PausedScannerCard({
  integration,
  onChanged,
}: {
  integration: Integration
  onChanged: () => void
}) {
  const [deleteOpen, setDeleteOpen] = useState(false)
  const { trigger: deleteIntegration, isMutating: deleting } = useDeleteIntegrationApi(
    integration.id
  )

  const mode = getConfigString(integration, 'execution_mode') || 'sensor'
  const engine = getConfigString(integration, 'engine')

  async function handleDelete() {
    try {
      await deleteIntegration()
      toast.success('Scanner removed')
      setDeleteOpen(false)
      onChanged()
    } catch {
      toast.error('Failed to remove scanner')
    }
  }

  return (
    <Card>
      <CardContent className="pt-6">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0 flex-1 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="truncate font-semibold">{integration.name}</h3>
              <Badge variant="outline" className="text-xs">
                <PauseCircle className="me-1 h-3 w-3" />
                Paused
              </Badge>
              <StatusBadge status={integration.status} />
              <Badge variant="secondary" className="text-xs">
                {mode === 'sensor' ? 'Sensor' : 'Direct'}
              </Badge>
              {engine && (
                <Badge variant="outline" className="text-xs">
                  {engine === 'tenable_sc' ? 'Tenable.sc' : 'Nessus Pro'}
                </Badge>
              )}
            </div>
            {integration.base_url && (
              <p className="text-muted-foreground text-xs">{integration.base_url}</p>
            )}
            {integration.last_sync_at && (
              <span className="text-muted-foreground flex items-center gap-1 text-xs">
                <Clock className="h-3 w-3" />
                Last sync: {new Date(integration.last_sync_at).toLocaleString()}
              </span>
            )}
          </div>
          <Can permission={Permission.IntegrationsManage} mode="hide">
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setDeleteOpen(true)}
              title="Remove"
              aria-label={`Remove ${integration.name}`}
              className="shrink-0 text-red-500 hover:text-red-600"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </Can>
        </div>
      </CardContent>

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title={`Remove ${integration.name}?`}
        desc="This removes the scanner integration from OpenCTEM. Findings already ingested are kept."
        confirmText={deleting ? 'Removing...' : 'Remove'}
        destructive
        isLoading={deleting}
        handleConfirm={() => void handleDelete()}
      />
    </Card>
  )
}

// ─────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────

function LoadingSkeleton() {
  return (
    <Main>
      <Skeleton className="mb-6 h-8 w-56" />
      <Skeleton className="h-20 rounded-lg" />
      <div className="mt-6 space-y-4">
        {Array.from({ length: 2 }).map((_, i) => (
          <Skeleton key={i} className="h-28 rounded-lg" />
        ))}
      </div>
    </Main>
  )
}

export function ScannerImportsView() {
  const [importOpen, setImportOpen] = useState(false)
  const {
    data,
    isLoading,
    mutate: reload,
  } = useIntegrationsApi({ category: 'security', per_page: 50 })

  // Only Tenable rows belong to this page; they are all paused.
  const paused = (data?.data ?? []).filter((s) => s.provider === 'tenable')

  const refresh = () => {
    reload()
    // Invalidate every integrations list query (any category/pagination), not a
    // single hard-coded key — the live hook key includes &per_page=50.
    void invalidateIntegrationsCache()
  }

  if (isLoading) return <LoadingSkeleton />

  return (
    <Main>
      <PageHeader
        title="Vulnerability scanners"
        description="Import Nessus and Tenable scan exports as assets and findings"
      >
        <Can permission={IMPORT_PERMISSIONS} requireAll mode="hide">
          <Button size="sm" onClick={() => setImportOpen(true)}>
            <Upload className="me-2 h-4 w-4" />
            Import .nessus
          </Button>
        </Can>
      </PageHeader>

      <Alert className="mt-6">
        <PauseCircle className="h-4 w-4" />
        <AlertTitle>The live Tenable connector is paused</AlertTitle>
        <AlertDescription>
          Connecting Nessus Pro or Tenable.sc for rolling scan coverage is unavailable until the
          scanner runner is rebuilt on the sensor. Imports of .nessus exports work as before.
        </AlertDescription>
      </Alert>

      <div className="mt-6">
        {paused.length === 0 ? (
          <EmptyState
            icon={ShieldCheck}
            title="Import scan results"
            description="Upload a .nessus export: hosts become assets and vulnerabilities become findings."
            action={
              <Can permission={IMPORT_PERMISSIONS} requireAll mode="hide">
                <Button size="sm" onClick={() => setImportOpen(true)}>
                  <Upload className="me-2 h-4 w-4" />
                  Import .nessus
                </Button>
              </Can>
            }
          />
        ) : (
          <>
            <h2 className="mb-1 text-lg font-semibold">Paused connectors</h2>
            <p className="text-muted-foreground mb-4 text-sm">
              Created before the pause. They do not scan; remove them or keep them for when the
              connector returns.
            </p>
            <div className="space-y-4">
              {paused.map((s) => (
                <PausedScannerCard key={s.id} integration={s} onChanged={refresh} />
              ))}
            </div>
          </>
        )}
      </div>

      <ImportResultsDialog open={importOpen} onOpenChange={setImportOpen} onSuccess={refresh} />
    </Main>
  )
}
