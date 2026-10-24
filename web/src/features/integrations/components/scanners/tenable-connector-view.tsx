'use client'

/**
 * Settings > Integrations > Vulnerability scanners with the Tenable.sc
 * connector on (api docs/rfcs/RFC-047), as Beta. Rendered while
 * TENABLE_CONNECTOR_ENABLED (features/integrations/config/feature-gates.ts),
 * which stays equal to the API's integration.TenableConnectorEnabled.
 *
 * A connector is a Tenable integration whose sensor pulls from Tenable.sc and
 * launches its scans; the Tenable credentials stay on that sensor. Older
 * Tenable rows (Nessus Pro, direct mode) have no runner and are listed as
 * paused with Remove only.
 */

import { useMemo, useState } from 'react'
import { Plus, ShieldCheck, Upload } from 'lucide-react'

import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  invalidateIntegrationsCache,
  useIntegrationsApi,
} from '@/features/integrations/api/use-integrations-api'
import { isTenableSCConnector, readConnectorSettings } from '@/features/integrations/lib/tenable-sc'
import type { Integration } from '@/features/integrations/types/integration.types'
import { EmptyState, PageHeader, PageStack } from '@/features/shared'
import { useAllSensors } from '@/lib/api/sensor-hooks'
import { Can, Permission } from '@/lib/permissions'
import { PausedScannerCard } from './scanner-imports-view'
import { ImportResultsDialog } from '@/features/findings/components/import-results-dialog'
import { TenableConnectorCard } from './tenable-connector-card'
import { TenableConnectorDialog } from './tenable-connector-dialog'
import { TenableCoveragePanel } from './tenable-coverage-panel'
import { useTranslation } from '@/context/i18n-provider'

export function TenableConnectorView() {
  const { t } = useTranslation()
  const [dialog, setDialog] = useState<{ open: boolean; integration?: Integration }>({
    open: false,
  })
  const [importOpen, setImportOpen] = useState(false)
  const {
    data,
    isLoading,
    mutate: reload,
  } = useIntegrationsApi({ category: 'security', per_page: 50 })
  const { data: sensorsData } = useAllSensors()

  const tenable = useMemo(
    () => (data?.data ?? []).filter((i) => i.provider === 'tenable'),
    [data?.data]
  )
  const connectors = useMemo(() => tenable.filter(isTenableSCConnector), [tenable])
  const paused = useMemo(() => tenable.filter((i) => !isTenableSCConnector(i)), [tenable])
  const coverage = connectors.find((c) => readConnectorSettings(c).coverageEnabled) ?? connectors[0]
  const sensorById = useMemo(
    () => new Map((sensorsData?.items ?? []).map((s) => [s.id, s])),
    [sensorsData?.items]
  )

  const refresh = () => {
    void reload()
    void invalidateIntegrationsCache()
  }
  const openCreate = () => setDialog({ open: true })

  if (isLoading) {
    return (
      <Main>
        <PageStack>
          <Skeleton className="h-10 w-72" />
          <Skeleton className="h-40 w-full" />
        </PageStack>
      </Main>
    )
  }

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('tenableSc.view.title', 'Vulnerability scanners')}
          description={t(
            'tenableSc.view.description',
            'Pull from Tenable.sc and launch its scans through one of your sensors'
          )}
        >
          <Can
            permission={[Permission.AssetsWrite, Permission.FindingsWrite]}
            requireAll
            mode="hide"
          >
            <Button variant="outline" size="sm" onClick={() => setImportOpen(true)}>
              <Upload className="me-2 h-4 w-4" />
              {t('tenableSc.view.importNessus', 'Import .nessus')}
            </Button>
          </Can>
          <Can permission={Permission.IntegrationsManage} mode="hide">
            <Button size="sm" onClick={openCreate}>
              <Plus className="me-2 h-4 w-4" />
              {t('tenableSc.view.connect', 'Connect Tenable.sc')}
            </Button>
          </Can>
        </PageHeader>

        {coverage && (
          <section className="mt-5" aria-labelledby="tsc-coverage-heading">
            <h2 id="tsc-coverage-heading" className="mb-3 text-lg font-semibold">
              {t('tenableSc.view.coverage', 'Coverage')}
            </h2>
            <TenableCoveragePanel integration={coverage} onChanged={refresh} />
          </section>
        )}

        <section className="mt-5" aria-labelledby="tsc-connectors-heading">
          <div className="mb-3 flex items-center gap-2">
            <h2 id="tsc-connectors-heading" className="text-lg font-semibold">
              {t('tenableSc.view.connectors', 'Connectors')}
            </h2>
            <Badge variant="outline">{t('tenableSc.beta', 'Beta')}</Badge>
          </div>
          {connectors.length === 0 ? (
            <EmptyState
              icon={ShieldCheck}
              title={t('tenableSc.view.emptyTitle', 'No Tenable.sc connector')}
              description={t(
                'tenableSc.view.emptyDescription',
                'Configure the connector on one of your sensors, then connect it here. The Tenable.sc API keys stay on the sensor.'
              )}
              action={
                <Can permission={Permission.IntegrationsManage} mode="hide">
                  <Button size="sm" onClick={openCreate}>
                    <Plus className="me-2 h-4 w-4" />
                    {t('tenableSc.view.connect', 'Connect Tenable.sc')}
                  </Button>
                </Can>
              }
            />
          ) : (
            <div className="space-y-4">
              {connectors.map((c) => (
                <TenableConnectorCard
                  key={c.id}
                  integration={c}
                  sensor={sensorById.get(readConnectorSettings(c).sensorId)}
                  onEdit={() => setDialog({ open: true, integration: c })}
                  onChanged={refresh}
                />
              ))}
            </div>
          )}
        </section>

        {paused.length > 0 && (
          <section className="mt-5" aria-labelledby="tsc-paused-heading">
            <h2 id="tsc-paused-heading" className="mb-3 text-lg font-semibold">
              {t('tenableSc.view.pausedTitle', 'Paused Tenable integrations')}
            </h2>
            <p className="text-muted-foreground mb-3 text-sm">
              {t(
                'settings.scanners.pausedRows',
                'Nessus Pro and direct connections are no longer supported. Remove them, or connect Tenable.sc through a sensor.'
              )}
            </p>
            <div className="space-y-4">
              {paused.map((p) => (
                <PausedScannerCard key={p.id} integration={p} onChanged={refresh} />
              ))}
            </div>
          </section>
        )}

        <TenableConnectorDialog
          open={dialog.open}
          integration={dialog.integration}
          onOpenChange={(open) => setDialog((d) => ({ ...d, open }))}
          onSaved={refresh}
        />
        <ImportResultsDialog
          open={importOpen}
          onOpenChange={setImportOpen}
          onImported={refresh}
          minSeverity="low"
        />
      </PageStack>
    </Main>
  )
}
