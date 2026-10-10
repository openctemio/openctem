'use client'

/**
 * The scanner_config of a Tenable.sc scan (api RFC-047 §5.2): which
 * connector launches it, with which Tenable.sc scan policy, repository and
 * (optional) zone. The pickers list what the connector's sensor reported its
 * owner allows; the API and the sensor refuse anything else.
 */

import { useMemo } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import Link from '@/components/link'

import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useIntegrationsApi } from '@/features/integrations/api/use-integrations-api'
import { CatalogSelect } from '@/features/integrations/components/scanners/catalog-select'
import {
  isTenableSCConnector,
  readTenableScanConfig,
  readTenableSync,
  tenableScanConfigToApi,
  type TenableScanConfig,
} from '@/features/integrations/lib/tenable-sc'

interface TenableScanFieldsProps {
  value: Record<string, unknown> | undefined
  onChange: (config: Record<string, unknown>) => void
}

export function TenableScanFields({ value, onChange }: TenableScanFieldsProps) {
  const { t } = useTranslation()
  const { data, isLoading } = useIntegrationsApi({ category: 'security', per_page: 50 })
  const connectors = useMemo(() => (data?.data ?? []).filter(isTenableSCConnector), [data?.data])
  const cfg = readTenableScanConfig(value)
  const selected = connectors.find((c) => c.id === cfg.integrationId)
  const catalog = readTenableSync(selected).catalog

  const set = (patch: Partial<TenableScanConfig>) =>
    onChange(tenableScanConfigToApi({ ...cfg, ...patch }, value))

  return (
    <div className="space-y-3 rounded-lg border p-3">
      <div className="space-y-2">
        <Label htmlFor="tsc-scan-connector">
          {t('scans.tenable.connector')} <span className="text-destructive">*</span>
        </Label>
        <Select
          value={cfg.integrationId || undefined}
          onValueChange={(integrationId) =>
            // A different connector has its own allow-list: start the picks over.
            set({ integrationId, policyId: 0, repositoryId: 0, zoneId: 0 })
          }
        >
          <SelectTrigger id="tsc-scan-connector" aria-label={t('scans.tenable.connector')}>
            <SelectValue
              placeholder={
                isLoading
                  ? t('scans.tenable.loading')
                  : connectors.length === 0
                    ? t('scans.tenable.none')
                    : t('scans.tenable.choose')
              }
            />
          </SelectTrigger>
          <SelectContent>
            {connectors.map((c) => (
              <SelectItem key={c.id} value={c.id}>
                {c.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {!isLoading && connectors.length === 0 && (
          <p className="text-muted-foreground text-xs">
            <Link href="/settings/integrations/scanners" className="underline">
              {t('scans.tenable.connectLink')}
            </Link>
          </p>
        )}
      </div>

      {cfg.integrationId && (
        <>
          <CatalogSelect
            id="tsc-scan-policy"
            label={t('scans.tenable.policy')}
            items={catalog?.policies}
            value={cfg.policyId}
            onChange={(policyId) => set({ policyId })}
            required
          />
          <CatalogSelect
            id="tsc-scan-repo"
            label={t('scans.tenable.repository')}
            items={catalog?.scanRepositories}
            value={cfg.repositoryId}
            onChange={(repositoryId) => set({ repositoryId })}
            required
          />
          {(catalog?.scanZones.length ?? 0) > 0 && (
            <CatalogSelect
              id="tsc-scan-zone"
              label={t('scans.tenable.zone')}
              items={catalog?.scanZones}
              value={cfg.zoneId}
              onChange={(zoneId) => set({ zoneId })}
              optional
            />
          )}
          <p className="text-muted-foreground text-xs">{t('scans.tenable.note')}</p>
        </>
      )}
    </div>
  )
}
