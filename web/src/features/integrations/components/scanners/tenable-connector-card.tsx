'use client'

/**
 * One Tenable.sc sensor connector: its sensor, sync status and cursor, what
 * the sensor allows (repositories, policies), and the actions an
 * integrations manager may take (Sync now, Edit, Remove).
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { AlertTriangle, Pencil, RefreshCw, Trash2 } from 'lucide-react'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import {
  useDeleteIntegrationApi,
  useSyncIntegrationApi,
} from '@/features/integrations/api/use-integrations-api'
import {
  readConnectorSettings,
  readTenableSync,
  type CatalogItem,
} from '@/features/integrations/lib/tenable-sc'
import type { Integration } from '@/features/integrations/types/integration.types'
import { RelativeTime } from '@/features/shared'
import type { Sensor } from '@/lib/api/sensor-types'
import { Can, Permission } from '@/lib/permissions'
import { StatusBadge } from './shared'

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : 'Request failed'
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-muted-foreground text-xs">{label}</dt>
      <dd className="truncate text-sm">{children}</dd>
    </div>
  )
}

function CatalogList({ label, items }: { label: string; items: CatalogItem[] }) {
  return (
    <div className="min-w-0">
      <p className="text-muted-foreground mb-1 text-xs">{label}</p>
      {items.length === 0 ? (
        <p className="text-muted-foreground text-sm">None allowed</p>
      ) : (
        <div className="flex flex-wrap gap-1">
          {items.map((i) => (
            <Badge key={i.id} variant="secondary" className="font-normal">
              {i.name}
            </Badge>
          ))}
        </div>
      )}
    </div>
  )
}

interface TenableConnectorCardProps {
  integration: Integration
  sensor?: Sensor
  onEdit: () => void
  onChanged: () => void
}

export function TenableConnectorCard({
  integration,
  sensor,
  onEdit,
  onChanged,
}: TenableConnectorCardProps) {
  const sync = readTenableSync(integration)
  const settings = readConnectorSettings(integration)
  const [confirmRemove, setConfirmRemove] = useState(false)
  const { trigger: syncNow, isMutating: syncing } = useSyncIntegrationApi(integration.id)
  const { trigger: remove, isMutating: removing } = useDeleteIntegrationApi(integration.id)
  const running = Boolean(sync.openCommandId)

  async function handleSync() {
    try {
      await syncNow()
      toast.success('Sync queued for the sensor')
      onChanged()
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }

  async function handleRemove() {
    try {
      await remove()
      toast.success('Connector removed')
      onChanged()
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setConfirmRemove(false)
    }
  }

  return (
    <Card>
      <CardContent className="space-y-4 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="truncate font-semibold">{integration.name}</h3>
              <StatusBadge status={integration.status} />
              {running && (
                <Badge variant="outline" className="border-primary/30 text-primary">
                  {sync.openMode === 'full' ? 'Full sync running' : 'Sync running'}
                </Badge>
              )}
            </div>
            <p className="text-muted-foreground text-sm">
              Sensor {sensor?.name ?? settings.sensorId ?? 'unknown'} · instance {settings.instance}
              {sync.tenableVersion ? ` · Tenable.sc ${sync.tenableVersion}` : ''}
            </p>
          </div>
          <Can permission={Permission.IntegrationsManage} mode="hide">
            <div className="flex flex-wrap gap-2">
              <Button size="sm" onClick={handleSync} disabled={syncing || running}>
                <RefreshCw className="me-2 h-4 w-4" />
                Sync now
              </Button>
              <Button size="sm" variant="outline" onClick={onEdit} aria-label="Edit connector">
                <Pencil className="h-4 w-4" />
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => setConfirmRemove(true)}
                aria-label="Remove connector"
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            </div>
          </Can>
        </div>

        {integration.sync_error && (
          <div className="flex gap-2 rounded-lg border border-destructive/30 bg-destructive/10 p-3">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
            <p className="text-sm text-destructive">{integration.sync_error}</p>
          </div>
        )}

        <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Fact label="Last outcome">
            {sync.lastOutcome === 'completed'
              ? 'Completed'
              : sync.lastOutcome === 'failed'
                ? 'Failed'
                : 'No sync yet'}
          </Fact>
          <Fact label="Synced up to">
            <RelativeTime date={sync.lastSuccessfulSync} />
          </Fact>
          <Fact label="Last full sync">
            <RelativeTime date={sync.lastFullSync} />
          </Fact>
          <Fact label="Next sync">
            <RelativeTime date={integration.next_sync_at} />
          </Fact>
          <Fact label="Hosts">{sync.lastSuccessfulSync ? sync.hosts : 'Not enough data'}</Fact>
          <Fact label="Open vulnerabilities">
            {sync.lastSuccessfulSync ? sync.open : 'Not enough data'}
          </Fact>
          <Fact label="Mitigated (last window)">
            {sync.lastSuccessfulSync ? sync.mitigated : 'Not enough data'}
          </Fact>
          <Fact label="Plugins">{sync.lastSuccessfulSync ? sync.plugins : 'Not enough data'}</Fact>
        </dl>

        <div className="border-t pt-3">
          <p className="mb-2 text-sm font-medium">Allowed by the sensor&apos;s owner</p>
          {sync.catalog ? (
            <div className="grid gap-3 md:grid-cols-3">
              <CatalogList label="Repositories read" items={sync.catalog.repositories} />
              <CatalogList label="Scan policies" items={sync.catalog.policies} />
              <CatalogList label="Scan repositories" items={sync.catalog.scanRepositories} />
            </div>
          ) : (
            <p className="text-muted-foreground text-sm">
              Reported by the sensor after its first successful sync.
            </p>
          )}
        </div>
      </CardContent>

      <ConfirmDialog
        open={confirmRemove}
        onOpenChange={setConfirmRemove}
        title={`Remove ${integration.name}?`}
        desc="Syncs and coverage through this connector stop. Findings already pulled are kept."
        confirmText={removing ? 'Removing...' : 'Remove'}
        destructive
        isLoading={removing}
        handleConfirm={() => void handleRemove()}
      />
    </Card>
  )
}
