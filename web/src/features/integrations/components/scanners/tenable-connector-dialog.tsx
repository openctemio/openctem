'use client'

/**
 * Create or edit a Tenable.sc sensor connector (api RFC-047). The platform
 * stores no Tenable credentials and no Tenable URL: the connector's keys live
 * in the sensor's own config file. Here the owner picks one of the tenant's
 * sensors and the instance name used in that file.
 */

import { useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'
import { ServerCog } from 'lucide-react'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  useCreateIntegrationApi,
  useUpdateIntegrationApi,
} from '@/features/integrations/api/use-integrations-api'
import {
  DEFAULT_CONNECTOR_SETTINGS,
  connectorConfig,
  connectorSensorOptions,
  connectorSettingsError,
  readConnectorSettings,
  readTenableSync,
  type ConnectorSettings,
} from '@/features/integrations/lib/tenable-sc'
import type { Integration } from '@/features/integrations/types/integration.types'
import { useAllSensors } from '@/lib/api/sensor-hooks'
import { CatalogSelect } from './catalog-select'

const SEVERITIES = [
  { value: 0, label: 'Info and above' },
  { value: 1, label: 'Low and above' },
  { value: 2, label: 'Medium and above' },
  { value: 3, label: 'High and above' },
  { value: 4, label: 'Critical only' },
]

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : 'Request failed'
}

interface TenableConnectorDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Edit this connector; create one when absent. */
  integration?: Integration
  onSaved: () => void
}

export function TenableConnectorDialog({
  open,
  onOpenChange,
  integration,
  onSaved,
}: TenableConnectorDialogProps) {
  const editing = Boolean(integration)
  const [name, setName] = useState('')
  const [settings, setSettings] = useState<ConnectorSettings>(DEFAULT_CONNECTOR_SETTINGS)
  const { data: sensorsData, isLoading: sensorsLoading } = useAllSensors(undefined, open)
  const options = useMemo(() => connectorSensorOptions(sensorsData?.items), [sensorsData?.items])
  const catalog = readTenableSync(integration).catalog

  const { trigger: create, isMutating: creating } = useCreateIntegrationApi()
  const { trigger: update, isMutating: updating } = useUpdateIntegrationApi(integration?.id ?? '')

  useEffect(() => {
    if (!open) return
    setName(integration?.name ?? 'Tenable.sc')
    setSettings(integration ? readConnectorSettings(integration) : DEFAULT_CONNECTOR_SETTINGS)
  }, [open, integration])

  const set = (patch: Partial<ConnectorSettings>) => setSettings((s) => ({ ...s, ...patch }))
  const selected = options.find((o) => o.sensor.id === settings.sensorId)

  async function save() {
    const problem = !name.trim() ? 'Enter a name' : connectorSettingsError(settings)
    if (problem) {
      toast.error(problem)
      return
    }
    const config = connectorConfig(settings, integration?.config)
    try {
      if (integration) {
        await update({ name: name.trim(), config })
        toast.success('Connector updated')
      } else {
        await create({
          name: name.trim(),
          category: 'security',
          provider: 'tenable',
          auth_type: 'api_key',
          config,
        })
        toast.success('Connector added. The first sync starts within a few minutes.')
      }
      onSaved()
      onOpenChange(false)
    } catch (err) {
      toast.error(errorMessage(err))
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{editing ? 'Edit Tenable.sc connector' : 'Connect Tenable.sc'}</DialogTitle>
          <DialogDescription>
            One of your sensors pulls from Tenable.sc and launches its scans. The Tenable.sc API
            keys stay in that sensor&apos;s config file; OpenCTEM never stores them.
          </DialogDescription>
        </DialogHeader>

        <DialogBody>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="tsc-name">Name</Label>
              <Input id="tsc-name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>

            <div className="space-y-2">
              <Label htmlFor="tsc-sensor">
                Sensor <span className="text-destructive">*</span>
              </Label>
              <Select
                value={settings.sensorId || undefined}
                onValueChange={(v) => set({ sensorId: v })}
              >
                <SelectTrigger id="tsc-sensor" aria-label="Sensor">
                  <SelectValue
                    placeholder={
                      sensorsLoading
                        ? 'Loading sensors…'
                        : options.length === 0
                          ? 'No active sensor of your own'
                          : 'Choose a sensor'
                    }
                  />
                </SelectTrigger>
                <SelectContent>
                  {options.map(({ sensor, runsConnector }) => (
                    <SelectItem key={sensor.id} value={sensor.id}>
                      {sensor.name}
                      {runsConnector ? ' (runs the connector)' : ' (connector not configured)'}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {selected && !selected.runsConnector && (
                <p className="text-xs text-warning">
                  This sensor does not report the Tenable.sc connector yet. Configure it on the
                  sensor (docs/TENABLE_SC.md in the sensor repository); syncs are refused until it
                  does.
                </p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="tsc-instance">Instance name</Label>
              <Input
                id="tsc-instance"
                value={settings.instance}
                onChange={(e) => set({ instance: e.target.value.trim().toLowerCase() })}
              />
              <p className="text-muted-foreground text-xs">
                The name of the Tenable.sc instance in the sensor&apos;s connector config (default
                for the environment-variable setup).
              </p>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="tsc-severity">Pull findings</Label>
                <Select
                  value={String(settings.minSeverity)}
                  onValueChange={(v) => set({ minSeverity: Number(v) })}
                >
                  <SelectTrigger id="tsc-severity" aria-label="Minimum severity">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SEVERITIES.map((s) => (
                      <SelectItem key={s.value} value={String(s.value)}>
                        {s.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="tsc-full">Full sync every (days)</Label>
                <Input
                  id="tsc-full"
                  type="number"
                  min={1}
                  max={90}
                  value={settings.fullSyncDays}
                  onChange={(e) => set({ fullSyncDays: Number(e.target.value) || 0 })}
                />
              </div>
            </div>

            <div className="space-y-3 rounded-lg border p-3">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <Label htmlFor="tsc-coverage">Rolling coverage</Label>
                  <p className="text-muted-foreground text-xs">
                    Scan the inventory in license-sized batches through this connector.
                  </p>
                </div>
                <Switch
                  id="tsc-coverage"
                  checked={settings.coverageEnabled}
                  onCheckedChange={(v) => set({ coverageEnabled: v })}
                />
              </div>
              {settings.coverageEnabled && (
                <div className="space-y-3">
                  <CatalogSelect
                    id="tsc-cov-policy"
                    label="Scan policy"
                    items={catalog?.policies}
                    value={settings.coveragePolicyId}
                    onChange={(v) => set({ coveragePolicyId: v })}
                    required
                  />
                  <CatalogSelect
                    id="tsc-cov-repo"
                    label="Scan repository"
                    items={catalog?.scanRepositories}
                    value={settings.coverageRepositoryId}
                    onChange={(v) => set({ coverageRepositoryId: v })}
                    required
                  />
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="tsc-cap">License cap (optional)</Label>
                      <Input
                        id="tsc-cap"
                        type="number"
                        min={0}
                        value={settings.licenseCap || ''}
                        placeholder="Tenable.sc license"
                        onChange={(e) => set({ licenseCap: Number(e.target.value) || 0 })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="tsc-margin">Safety margin (IPs)</Label>
                      <Input
                        id="tsc-margin"
                        type="number"
                        min={0}
                        value={settings.safetyMargin || ''}
                        placeholder="0"
                        onChange={(e) => set({ safetyMargin: Number(e.target.value) || 0 })}
                      />
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="bg-muted/50 flex gap-2 rounded-lg border p-3">
              <ServerCog className="text-muted-foreground mt-0.5 h-4 w-4 shrink-0" />
              <p className="text-muted-foreground text-xs">
                What the connector may read and which policies and repositories scans may use are
                set by the sensor&apos;s owner in its config; OpenCTEM can only ask within them.
              </p>
            </div>
          </div>
        </DialogBody>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={save} disabled={creating || updating}>
            {editing ? 'Save' : 'Connect'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
