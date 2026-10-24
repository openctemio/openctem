'use client'

/**
 * One Tenable.sc sensor connector: its sensor, sync status and cursor, what
 * the sensor allows (repositories, policies), and the actions an
 * integrations manager may take (Sync now, Edit, Remove).
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { AlertTriangle, Pencil, RefreshCw, Trash2 } from 'lucide-react'

import { nameToTypeToConfirm } from '@/components/confirm-name'
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
import { useTranslation } from '@/context/i18n-provider'

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-muted-foreground text-xs">{label}</dt>
      <dd className="truncate text-sm">{children}</dd>
    </div>
  )
}

function CatalogList({ label, items }: { label: string; items: CatalogItem[] }) {
  const { t } = useTranslation()
  return (
    <div className="min-w-0">
      <p className="text-muted-foreground mb-1 text-xs">{label}</p>
      {items.length === 0 ? (
        <p className="text-muted-foreground text-sm">
          {t('tenableSc.card.noneAllowed', 'None allowed')}
        </p>
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
  const { t } = useTranslation()
  const sync = readTenableSync(integration)
  const settings = readConnectorSettings(integration)
  const [confirmRemove, setConfirmRemove] = useState(false)
  const { trigger: syncNow, isMutating: syncing } = useSyncIntegrationApi(integration.id)
  const { trigger: remove, isMutating: removing } = useDeleteIntegrationApi(integration.id)
  const running = Boolean(sync.openCommandId)
  const errorMessage = (err: unknown) =>
    err instanceof Error ? err.message : t('tenableSc.card.requestFailed', 'Request failed')
  const notEnough = t('tenableSc.card.notEnoughData', 'Not enough data')

  async function handleSync() {
    try {
      await syncNow()
      toast.success(t('tenableSc.card.syncQueued', 'Sync queued for the sensor'))
      onChanged()
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }

  async function handleRemove() {
    try {
      await remove()
      toast.success(t('tenableSc.card.removed', 'Connector removed'))
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
              <Badge variant="outline">{t('tenableSc.beta', 'Beta')}</Badge>
              <StatusBadge status={integration.status} />
              {running && (
                <Badge variant="outline" className="border-primary/30 text-primary">
                  {sync.openMode === 'full'
                    ? t('tenableSc.card.fullSyncRunning', 'Full sync running')
                    : t('tenableSc.card.syncRunning', 'Sync running')}
                </Badge>
              )}
            </div>
            <p className="text-muted-foreground text-sm">
              {t('tenableSc.card.sensorInstance', 'Sensor {sensor} · instance {instance}', {
                sensor:
                  sensor?.name || settings.sensorId || t('tenableSc.card.unknownSensor', 'unknown'),
                instance: settings.instance,
              })}
              {sync.tenableVersion
                ? t('tenableSc.card.tenableVersion', ' · Tenable.sc {version}', {
                    version: sync.tenableVersion,
                  })
                : ''}
            </p>
          </div>
          <Can permission={Permission.IntegrationsManage} mode="hide">
            <div className="flex flex-wrap gap-2">
              <Button size="sm" onClick={handleSync} disabled={syncing || running}>
                <RefreshCw className="me-2 h-4 w-4" />
                {t('tenableSc.card.syncNow', 'Sync now')}
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={onEdit}
                aria-label={t('tenableSc.card.edit', 'Edit connector')}
              >
                <Pencil className="h-4 w-4" />
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="ms-3 text-destructive hover:text-destructive"
                onClick={() => setConfirmRemove(true)}
                aria-label={t('tenableSc.card.remove', 'Remove connector')}
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
          <Fact label={t('tenableSc.card.lastOutcome', 'Last outcome')}>
            {sync.lastOutcome === 'completed'
              ? t('tenableSc.card.completed', 'Completed')
              : sync.lastOutcome === 'failed'
                ? t('tenableSc.card.failed', 'Failed')
                : t('tenableSc.card.noSyncYet', 'No sync yet')}
          </Fact>
          <Fact label={t('tenableSc.card.syncedUpTo', 'Synced up to')}>
            <RelativeTime date={sync.lastSuccessfulSync} />
          </Fact>
          <Fact label={t('tenableSc.card.lastFullSync', 'Last full sync')}>
            <RelativeTime date={sync.lastFullSync} />
          </Fact>
          <Fact label={t('tenableSc.card.nextSync', 'Next sync')}>
            <RelativeTime date={integration.next_sync_at} />
          </Fact>
          <Fact label={t('tenableSc.card.hosts', 'Hosts')}>
            {sync.lastSuccessfulSync ? sync.hosts : notEnough}
          </Fact>
          <Fact label={t('tenableSc.card.openVulnerabilities', 'Open vulnerabilities')}>
            {sync.lastSuccessfulSync ? sync.open : notEnough}
          </Fact>
          <Fact label={t('tenableSc.card.mitigated', 'Mitigated (last window)')}>
            {sync.lastSuccessfulSync ? sync.mitigated : notEnough}
          </Fact>
          <Fact label={t('tenableSc.card.plugins', 'Plugins')}>
            {sync.lastSuccessfulSync ? sync.plugins : notEnough}
          </Fact>
        </dl>

        <div className="border-t pt-3">
          <p className="mb-2 text-sm font-medium">
            {t('tenableSc.card.allowedByOwner', "Allowed by the sensor's owner")}
          </p>
          {sync.catalog ? (
            <div className="grid gap-3 md:grid-cols-3">
              <CatalogList
                label={t('tenableSc.card.repositoriesRead', 'Repositories read')}
                items={sync.catalog.repositories}
              />
              <CatalogList
                label={t('tenableSc.card.scanPolicies', 'Scan policies')}
                items={sync.catalog.policies}
              />
              <CatalogList
                label={t('tenableSc.card.scanRepositories', 'Scan repositories')}
                items={sync.catalog.scanRepositories}
              />
            </div>
          ) : (
            <p className="text-muted-foreground text-sm">
              {t(
                'tenableSc.card.catalogPending',
                'Reported by the sensor after its first successful sync.'
              )}
            </p>
          )}
        </div>
      </CardContent>

      <ConfirmDialog
        open={confirmRemove}
        onOpenChange={setConfirmRemove}
        title={t('confirm.scannerIntegration.removeTitle', 'Remove the integration {name}?', {
          name: integration.name,
        })}
        desc={t(
          'confirm.scannerIntegration.removeConnectorDesc',
          'Syncs and coverage through this connector stop. Findings already pulled are kept. This cannot be undone.'
        )}
        confirmText={
          removing ? t('confirm.removing', 'Removing…') : t('confirm.scannerIntegration.removeBtn')
        }
        destructive
        typeToConfirm={nameToTypeToConfirm(integration.name, integration.id)}
        isLoading={removing}
        handleConfirm={() => void handleRemove()}
      />
    </Card>
  )
}
