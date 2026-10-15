'use client'

/**
 * Create or edit a Tenable.sc connector (api RFC-047). The connector runs as
 * its own image (ghcr.io/openctemio/connector-tenable), paired like a sensor;
 * the platform stores no Tenable credentials and no Tenable URL: the keys
 * live in the connector's config. Here the owner picks the connector's sensor
 * and the instance name used in its config.
 */

import { useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'
import { ServerCog } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
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
import { Checkbox } from '@/components/ui/checkbox'
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
  COVERAGE_ROTATIONS,
  DEFAULT_CONNECTOR_SETTINGS,
  MAX_ROTATION_WAIT_HOURS,
  MIN_ROTATION_WAIT_HOURS,
  connectorConfig,
  connectorSensorOptions,
  connectorSettingsError,
  readConnectorSettings,
  readTenableSync,
  type ConnectorSettings,
  type CoverageRotation,
} from '@/features/integrations/lib/tenable-sc'
import type { Integration } from '@/features/integrations/types/integration.types'
import { useAllSensors } from '@/lib/api/sensor-hooks'
import { useTranslation } from '@/context/i18n-provider'
import { CatalogSelect } from './catalog-select'

const SEVERITIES = [
  { value: 0, key: 'tenableSc.dialog.severity.info', label: 'Info and above' },
  { value: 1, key: 'tenableSc.dialog.severity.low', label: 'Low and above' },
  { value: 2, key: 'tenableSc.dialog.severity.medium', label: 'Medium and above' },
  { value: 3, key: 'tenableSc.dialog.severity.high', label: 'High and above' },
  { value: 4, key: 'tenableSc.dialog.severity.critical', label: 'Critical only' },
]

/** Each license rotation mode, with what it does (translated at render). */
const ROTATION_TEXT: Record<CoverageRotation, { label: string; hint: string }> = {
  off: {
    label: 'Off',
    hint: 'Covers what the license holds. Assets Tenable.sc already counts are rescanned; new ones only while the license has room.',
  },
  aging: {
    label: 'Aging',
    hint: "Tenable.sc's nightly cleanup frees the license from the rotation repository's data; the next batch is tried after the wait below.",
  },
  recycle: {
    label: 'Recycle',
    hint: 'The connector deletes and recreates its rotation repository before each batch, once the previous results are ingested.',
  },
}

/** The connector image an administrator runs next to Tenable.sc. */
export const CONNECTOR_IMAGE = 'ghcr.io/openctemio/connector-tenable'

/** The docker command that runs the connector (the pairing code comes from Settings > Sensors). */
export const CONNECTOR_RUN_COMMAND = [
  'docker run -d --name connector-tenable --restart unless-stopped \\',
  '  --read-only --cap-drop ALL --security-opt no-new-privileges:true \\',
  '  -e SENSOR_API_URL=<this console URL> -e SENSOR_PAIRING_CODE=<code> \\',
  '  -v connector-tenable-data:/var/lib/openctem \\',
  '  -v /etc/openctem/connectors:/etc/openctem/connectors:ro \\',
  '  -v /run/secrets/tenable-sc:/run/secrets/tenable-sc:ro \\',
  `  ${CONNECTOR_IMAGE}:<version>`,
].join('\n')

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
  const { t } = useTranslation()
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
    const settingsProblem = connectorSettingsError(settings)
    const problem = !name.trim()
      ? t('tenableSc.dialog.enterName', 'Enter a name')
      : settingsProblem && t(settingsProblem.key, settingsProblem.fallback)
    if (problem) {
      toast.error(problem)
      return
    }
    const config = connectorConfig(settings, integration?.config)
    try {
      if (integration) {
        await update({ name: name.trim(), config })
        toast.success(t('tenableSc.dialog.updated', 'Connector updated'))
      } else {
        await create({
          name: name.trim(),
          category: 'security',
          provider: 'tenable',
          auth_type: 'api_key',
          config,
        })
        toast.success(
          t(
            'tenableSc.dialog.added',
            'Connector added. The first sync starts within a few minutes.'
          )
        )
      }
      onSaved()
      onOpenChange(false)
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : t('tenableSc.dialog.failed', 'Request failed')
      )
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {editing
              ? t('tenableSc.dialog.editTitle', 'Edit Tenable.sc connector')
              : t('tenableSc.dialog.title', 'Connect Tenable.sc')}
            <Badge variant="outline">{t('tenableSc.beta', 'Beta')}</Badge>
          </DialogTitle>
          <DialogDescription>
            {t(
              'tenableSc.dialog.description',
              'The Tenable.sc connector runs as its own container next to your Tenable.sc, paired like a sensor. It pulls from Tenable.sc and launches its scans; the Tenable.sc API keys stay in its config, and {product} never stores them.'
            )}
          </DialogDescription>
        </DialogHeader>

        <DialogBody>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="tsc-name">{t('tenableSc.dialog.name', 'Name')}</Label>
              <Input id="tsc-name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>

            <div className="space-y-2">
              <Label htmlFor="tsc-sensor">
                {t('tenableSc.dialog.sensor', 'Connector sensor')}{' '}
                <span className="text-destructive">*</span>
              </Label>
              <Select
                value={settings.sensorId || undefined}
                onValueChange={(v) => set({ sensorId: v })}
              >
                <SelectTrigger
                  id="tsc-sensor"
                  aria-label={t('tenableSc.dialog.sensor', 'Connector sensor')}
                >
                  <SelectValue
                    placeholder={
                      sensorsLoading
                        ? t('tenableSc.dialog.loadingSensors', 'Loading sensors…')
                        : options.length === 0
                          ? t('tenableSc.dialog.noSensor', 'No active sensor of your own')
                          : t('tenableSc.dialog.chooseSensor', 'Choose the connector')
                    }
                  />
                </SelectTrigger>
                <SelectContent>
                  {options.map(({ sensor, runsConnector }) => (
                    <SelectItem key={sensor.id} value={sensor.id}>
                      {sensor.name}
                      {runsConnector
                        ? ` (${t('tenableSc.dialog.runsConnector', 'runs the connector')})`
                        : ` (${t('tenableSc.dialog.notConnector', 'not the connector')})`}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {selected && !selected.runsConnector && (
                <p className="text-xs text-warning">
                  {t(
                    'tenableSc.dialog.notConnectorHint',
                    'This sensor does not report the Tenable.sc connector. Pick the sensor of the connector image; syncs are refused until it reports the connector.'
                  )}
                </p>
              )}
              {!editing && (
                <div className="space-y-1.5 rounded-lg border p-3">
                  <p className="text-xs font-medium">
                    {t(
                      'tenableSc.dialog.installTitle',
                      'No connector yet? Run it next to Tenable.sc'
                    )}
                  </p>
                  <p className="text-muted-foreground text-xs">
                    {t(
                      'tenableSc.dialog.installHint',
                      'Add a sensor in Settings > Sensors with the scanner-connector profile to get a pairing code, write the connector config (instances, allow-lists, key file paths), then run:'
                    )}
                  </p>
                  <pre className="bg-muted overflow-x-auto rounded p-2 text-xs">
                    {CONNECTOR_RUN_COMMAND}
                  </pre>
                  <p className="text-muted-foreground text-xs">
                    {t(
                      'tenableSc.dialog.installDocs',
                      'Config keys, the least-privilege Tenable.sc user and image verification: github.com/openctemio/connector-tenable.'
                    )}
                  </p>
                </div>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="tsc-instance">
                {t('tenableSc.dialog.instance', 'Instance name')}
              </Label>
              <Input
                id="tsc-instance"
                value={settings.instance}
                onChange={(e) => set({ instance: e.target.value.trim().toLowerCase() })}
              />
              <p className="text-muted-foreground text-xs">
                {t(
                  'tenableSc.dialog.instanceHint',
                  'The name of the Tenable.sc instance in the connector config ("default" for the environment-variable setup).'
                )}
              </p>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="tsc-severity">
                  {t('tenableSc.dialog.pullFindings', 'Pull findings')}
                </Label>
                <Select
                  value={String(settings.minSeverity)}
                  onValueChange={(v) => set({ minSeverity: Number(v) })}
                >
                  <SelectTrigger
                    id="tsc-severity"
                    aria-label={t('tenableSc.dialog.minSeverity', 'Minimum severity')}
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SEVERITIES.map((s) => (
                      <SelectItem key={s.value} value={String(s.value)}>
                        {t(s.key, s.label)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="tsc-full">
                  {t('tenableSc.dialog.fullSyncDays', 'Full sync every (days)')}
                </Label>
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

            <div className="flex items-center justify-between gap-3 rounded-lg border p-3">
              <div>
                <Label htmlFor="tsc-in-scope">
                  {t('scope.connector.assetsInScope', 'Assets are in scope')}
                </Label>
                <p className="text-muted-foreground text-xs">
                  {t(
                    'scope.connector.assetsInScopeHint',
                    'After each sync, the public names and addresses this connector syncs get their exact scope entries, so scans may reach them. Turning this off keeps the entries already added.'
                  )}
                </p>
              </div>
              <Switch
                id="tsc-in-scope"
                checked={settings.assetsInScope}
                onCheckedChange={(v) => set({ assetsInScope: v })}
              />
            </div>

            <div className="space-y-3 rounded-lg border p-3">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <Label htmlFor="tsc-coverage">
                    {t('tenableSc.dialog.coverage', 'Rolling coverage')}
                  </Label>
                  <p className="text-muted-foreground text-xs">
                    {t(
                      'tenableSc.dialog.coverageHint',
                      'Scan the inventory in license-sized batches through this connector.'
                    )}
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
                    label={t('tenableSc.dialog.scanPolicy', 'Scan policy')}
                    items={catalog?.policies}
                    value={settings.coveragePolicyId}
                    onChange={(v) => set({ coveragePolicyId: v })}
                    required
                  />
                  <CatalogSelect
                    id="tsc-cov-repo"
                    label={t('tenableSc.dialog.scanRepository', 'Scan repository')}
                    items={catalog?.scanRepositories}
                    value={settings.coverageRepositoryId}
                    onChange={(v) => set({ coverageRepositoryId: v })}
                    required
                  />
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="tsc-cap">
                        {t('tenableSc.dialog.licenseCap', 'License cap (optional)')}
                      </Label>
                      <Input
                        id="tsc-cap"
                        type="number"
                        min={0}
                        value={settings.licenseCap || ''}
                        placeholder={t(
                          'tenableSc.dialog.licenseCapPlaceholder',
                          'Tenable.sc license'
                        )}
                        onChange={(e) => set({ licenseCap: Number(e.target.value) || 0 })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="tsc-margin">
                        {t('tenableSc.dialog.safetyMargin', 'Safety margin (IPs)')}
                      </Label>
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
                  <RotationFields settings={settings} onChange={set} />
                </div>
              )}
            </div>

            <div className="bg-muted/50 flex gap-2 rounded-lg border p-3">
              <ServerCog className="text-muted-foreground mt-0.5 h-4 w-4 shrink-0" />
              <p className="text-muted-foreground text-xs">
                {t(
                  'tenableSc.dialog.ownerLimits',
                  "What the connector may read and which policies and repositories scans may use are set by the connector's owner in its config; {product} can only ask within them."
                )}
              </p>
            </div>
          </div>
        </DialogBody>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('tenableSc.dialog.cancel', 'Cancel')}
          </Button>
          <Button onClick={save} disabled={creating || updating}>
            {editing
              ? t('tenableSc.dialog.save', 'Save')
              : t('tenableSc.dialog.connect', 'Connect')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** License rotation: the mode, the acknowledgement it needs and the aging wait. */
export function RotationFields({
  settings,
  onChange,
}: {
  settings: ConnectorSettings
  onChange: (patch: Partial<ConnectorSettings>) => void
}) {
  const { t } = useTranslation()
  const rotation = settings.rotation
  return (
    <div className="space-y-3 border-t pt-3">
      <div className="space-y-2">
        <Label htmlFor="tsc-rotation">{t('tenableSc.dialog.rotation', 'License rotation')}</Label>
        <Select
          value={rotation}
          onValueChange={(v) => onChange({ rotation: v as CoverageRotation })}
        >
          <SelectTrigger
            id="tsc-rotation"
            aria-label={t('tenableSc.dialog.rotation', 'License rotation')}
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {COVERAGE_ROTATIONS.map((r) => (
              <SelectItem key={r} value={r}>
                {t(`tenableSc.dialog.rotationMode.${r}`, ROTATION_TEXT[r].label)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-muted-foreground text-xs" data-testid="tsc-rotation-hint">
          {t(`tenableSc.dialog.rotationHint.${rotation}`, ROTATION_TEXT[rotation].hint)}
        </p>
      </div>
      {rotation !== 'off' && (
        <>
          <div className="flex items-start gap-2">
            <Checkbox
              id="tsc-rotation-ack"
              checked={settings.rotationAcknowledged}
              onCheckedChange={(v) => onChange({ rotationAcknowledged: v === true })}
              className="mt-0.5"
            />
            <Label htmlFor="tsc-rotation-ack" className="text-xs leading-snug font-normal">
              {t(
                'tenableSc.dialog.rotationAck',
                "I confirm this organization's Tenable license terms allow rotating more assets through the license than it holds"
              )}{' '}
              <span className="text-destructive">*</span>
            </Label>
          </div>
          {rotation === 'aging' && (
            <div className="space-y-2">
              <Label htmlFor="tsc-rotation-wait">
                {t('tenableSc.dialog.rotationWait', 'Wait after a batch (hours)')}
              </Label>
              <Input
                id="tsc-rotation-wait"
                type="number"
                min={MIN_ROTATION_WAIT_HOURS}
                max={MAX_ROTATION_WAIT_HOURS}
                value={settings.rotationWaitHours || ''}
                onChange={(e) => onChange({ rotationWaitHours: Number(e.target.value) || 0 })}
              />
              <p className="text-muted-foreground text-xs">
                {t(
                  'tenableSc.dialog.rotationWaitHint',
                  "1 to 72 hours, 12 by default. Match it to Tenable.sc's nightly cleanup; the license check before each batch confirms the capacity is free."
                )}
              </p>
            </div>
          )}
        </>
      )}
    </div>
  )
}
