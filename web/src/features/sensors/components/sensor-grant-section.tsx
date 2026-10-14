'use client'

/**
 * A sensor's grant (api docs/rfcs/RFC-052 §5): every dimension, what applies
 * now after the trust level, the trust control and the narrowing editor.
 *
 * The platform enforces the grant on every poll, claim and unsolicited
 * result. Narrowing needs sensors:grant:narrow; widening and promoting need
 * sensors:grant:widen. The server decides which a change is and answers 403
 * with its reason; the form only warns.
 */

import { useMemo, useState } from 'react'
import { AlertTriangle, Pencil, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { DetailCallout, DetailSection } from '@/features/shared'
import { ApiClientError } from '@/lib/api/error-handler'
import { useScanZones } from '@/lib/api/scan-zone-hooks'
import {
  grantUpdateRequest,
  updateSensorGrant,
  useSensorGrant,
  type SensorGrant,
} from '@/lib/api/sensor-grant-hooks'
import { Permission, useHasPermission } from '@/lib/permissions'

import type { Tr } from '../lib/format'
import { formatGrantList, profileLabel, targetNetworkLabel, tierLabel } from '../lib/grant'
import { SensorGrantEditDialog } from './sensor-grant-edit-dialog'
import { SensorGrantSuggestionCard } from './sensor-grant-suggestion-card'

/** The message to show for a failed grant change; a 409 also reloads. */
export function grantErrorMessage(err: unknown, tr?: Tr): string {
  if (err instanceof ApiClientError || (err && typeof err === 'object' && 'statusCode' in err)) {
    const e = err as { statusCode?: number; message?: string }
    if (e.statusCode === 409)
      return tr
        ? tr('sensors.grant.err.changed')
        : 'The grant changed since you opened it. It was reloaded; review it and try again.'
    if ((e.statusCode === 403 || e.statusCode === 400) && e.message) return e.message
  }
  return tr ? tr('sensors.grant.err.generic') : 'Could not change the grant'
}

export function isVersionConflict(err: unknown): boolean {
  return !!err && typeof err === 'object' && (err as { statusCode?: number }).statusCode === 409
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[10rem_1fr] gap-2 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  )
}

/** "Allowed" / "Not allowed", with what applies now when the trust level caps it. */
function Flag({ granted, effective }: { granted: boolean; effective?: boolean }) {
  const { t } = useTranslation()
  if (!granted) return <>{t('sensors.grantSection.notAllowed')}</>
  if (effective === false) return <>{t('sensors.grantSection.allowedOffWhileNew')}</>
  return <>{t('sensors.grantSection.allowed')}</>
}

export function TrustBadge({ level }: { level: string }) {
  const { t } = useTranslation()
  return level === 'trusted' ? (
    <Badge variant="secondary">{t('sensors.grantSection.trusted')}</Badge>
  ) : (
    <Badge variant="outline" className="border-warning text-warning">
      {t('sensors.grantSection.new')}
    </Badge>
  )
}

/**
 * Why a collector's reports are refused, when they are: its grant has no
 * push ingest, or the grant allows it and the sensor is not trusted. Null
 * when its reports are accepted. Mirrors the API's admission check.
 */
export function collectorRefusal(grant: SensorGrant): 'grant' | 'trust' | null {
  if (grant.effective?.allow_push_ingest) return null
  if (!grant.allow_push_ingest) return 'grant'
  return grant.trust_level === 'trusted' ? null : 'trust'
}

export function SensorGrantSection({
  sensorId,
  sensorType,
}: {
  sensorId: string
  /** The sensor's type: a collector gets an explanation when its reports are refused. */
  sensorType?: string
}) {
  const canRead = useHasPermission(Permission.SensorsRead)
  const canNarrow = useHasPermission(Permission.SensorsGrantNarrow)
  const canWiden = useHasPermission(Permission.SensorsGrantWiden)
  const canReadZones = useHasPermission(Permission.ScanZonesRead)
  const { data: grant, error, mutate } = useSensorGrant(sensorId, canRead)
  const { data: zonesData } = useScanZones(canReadZones)
  const zoneName = useMemo(() => {
    const m = new Map((zonesData?.data ?? []).map((z) => [z.id, z.name]))
    return (id: string) => m.get(id) ?? id
  }, [zonesData?.data])

  const [editOpen, setEditOpen] = useState(false)
  const [trustTarget, setTrustTarget] = useState<'trusted' | 'new' | null>(null)
  const { t } = useTranslation()
  const [saving, setSaving] = useState(false)

  if (!canRead) return null
  if (error) {
    return (
      <DetailSection title={t('sensors.grantSection.title')} icon={ShieldCheck}>
        <p className="text-sm text-muted-foreground">{t('sensors.grantSection.loadError')}</p>
      </DetailSection>
    )
  }
  if (!grant) return null

  const eff = grant.effective
  const isNew = grant.trust_level !== 'trusted'
  const refusal = collectorRefusal(grant)

  const changeTrust = async (to: 'trusted' | 'new') => {
    setSaving(true)
    try {
      const next = await updateSensorGrant(sensorId, grantUpdateRequest(grant, { trust_level: to }))
      await mutate(next, { revalidate: false })
      toast.success(
        to === 'trusted'
          ? t('sensors.grantSection.promoted')
          : t('sensors.grantSection.setBackToNew')
      )
      setTrustTarget(null)
    } catch (err) {
      toast.error(grantErrorMessage(err, t))
      if (isVersionConflict(err)) await mutate()
    } finally {
      setSaving(false)
    }
  }

  const scope =
    grant.target_cidrs === null && grant.target_domains === null
      ? t('sensors.grantEdit.any')
      : [...(grant.target_cidrs ?? []), ...(grant.target_domains ?? [])].join(', ') ||
        t('sensors.grantEdit.none')

  return (
    <DetailSection
      title={t('sensors.grantSection.title')}
      icon={ShieldCheck}
      actions={
        (canNarrow || canWiden) && (
          <Button variant="outline" size="sm" onClick={() => setEditOpen(true)}>
            <Pencil className="h-3.5 w-3.5" />
            {grant.legacy_broad
              ? t('sensors.grant.narrow', 'Narrow')
              : t('sensors.grant.edit', 'Edit')}
          </Button>
        )
      }
    >
      {grant.legacy_broad && (
        <div data-testid="legacy-broad-warning">
          <DetailCallout
            tone="warning"
            icon={AlertTriangle}
            title={t('sensors.grantSection.legacyTitle')}
          >
            {t('sensors.grantSection.legacyBody')}
          </DetailCallout>
        </div>
      )}

      {(canNarrow || canWiden) && (
        <SensorGrantSuggestionCard
          sensorId={sensorId}
          legacyBroad={grant.legacy_broad}
          onApplied={(next) => void mutate(next, { revalidate: false })}
        />
      )}

      {sensorType === 'collector' && refusal && (
        <div data-testid="collector-refused" data-missing={refusal}>
          <DetailCallout
            tone="warning"
            icon={AlertTriangle}
            title={
              refusal === 'trust'
                ? t(
                    'sensors.grant.collectorRefused.untrustedTitle',
                    "This collector's reports are refused: it is not trusted"
                  )
                : t(
                    'sensors.grant.collectorRefused.grantTitle',
                    "This collector's reports are refused: its grant does not allow them"
                  )
            }
          >
            <p>
              {refusal === 'trust'
                ? t(
                    'sensors.grant.collectorRefused.untrustedBody',
                    'Its grant allows asset reports, but a sensor that is not trusted cannot send results without a job, so the platform refuses every report it sends.'
                  )
                : t(
                    'sensors.grant.collectorRefused.grantBody',
                    'Its grant does not allow results without a job, so the platform refuses every report it sends.'
                  )}
            </p>
            {canWiden ? (
              <Button
                size="sm"
                variant="outline"
                className="mt-2"
                onClick={() =>
                  refusal === 'trust' ? setTrustTarget('trusted') : setEditOpen(true)
                }
              >
                {refusal === 'trust'
                  ? t('sensors.grant.collectorRefused.promote', 'Promote to Trusted')
                  : t('sensors.grant.collectorRefused.editGrant', 'Edit the grant')}
              </Button>
            ) : (
              <p className="mt-1 text-muted-foreground">
                {t(
                  'sensors.grant.collectorRefused.askAdmin',
                  'An administrator who may widen sensor grants can change this.'
                )}
              </p>
            )}
          </DetailCallout>
        </div>
      )}

      <dl className="space-y-1.5" data-testid="sensor-grant">
        <Row label={t('sensors.grantEdit.profile')}>{profileLabel(grant.profile, t)}</Row>
        <Row label={t('sensors.grantSection.trustLevel')}>
          <span className="inline-flex flex-wrap items-center gap-2">
            <TrustBadge level={grant.trust_level} />
            {isNew && canWiden && (
              <Button size="sm" variant="outline" onClick={() => setTrustTarget('trusted')}>
                {t('sensors.grantSection.promote')}
              </Button>
            )}
            {!isNew && canNarrow && (
              <Button size="sm" variant="ghost" onClick={() => setTrustTarget('new')}>
                {t('sensors.grantSection.setBack')}
              </Button>
            )}
          </span>
        </Row>
        <Row label={t('sensors.grantEdit.dim.jobTypes')}>
          {formatGrantList(grant.job_types, undefined, t)}
        </Row>
        <Row label={t('sensors.grantEdit.dim.zones')}>
          {formatGrantList(grant.zone_ids, zoneName, t)}
        </Row>
        <Row label={t('sensors.grantEdit.dim.tools')}>
          {formatGrantList(grant.tools, undefined, t)}
        </Row>
        <Row label={t('sensors.grantEdit.dim.capabilities')}>
          {formatGrantList(grant.capabilities, undefined, t)}
        </Row>
        <Row label={t('sensors.grantEdit.dim.tierCeiling')}>
          {tierLabel(grant.tier_ceiling, t)}
          {eff && eff.tier_ceiling < grant.tier_ceiling && (
            <span className="text-muted-foreground">
              {' '}
              ·{' '}
              {t('sensors.grantSection.tierWhileNew', undefined, {
                tier: tierLabel(eff.tier_ceiling, t),
              })}
            </span>
          )}
        </Row>
        <Row label={t('sensors.grantEdit.dim.targetNetwork')}>
          {targetNetworkLabel(grant.target_network, t)}
        </Row>
        <Row label={t('sensors.grantSection.targetScope')}>{scope}</Row>
        <Row label={t('sensors.grantSection.credentials')}>
          <Flag granted={grant.allow_credentials} effective={eff?.allow_credentials} />
        </Row>
        <Row label={t('sensors.grantSection.pushIngest')}>
          <Flag granted={grant.allow_push_ingest} effective={eff?.allow_push_ingest} />
        </Row>
        <Row label={t('sensors.grantEdit.dim.remoteActions')}>
          pause, drain{grant.remote_actions?.length ? `, ${grant.remote_actions.join(', ')}` : ''}
        </Row>
      </dl>

      <ConfirmDialog
        open={trustTarget !== null}
        onOpenChange={(o) => !o && setTrustTarget(null)}
        title={
          trustTarget === 'trusted'
            ? t('confirm.sensor.promoteTitle', 'Promote this sensor to Trusted?')
            : t('confirm.sensor.demoteTitle', 'Set this sensor back to New?')
        }
        desc={
          trustTarget === 'trusted'
            ? t(
                'confirm.sensor.promoteDesc',
                'A New sensor gets passive work only (T0), no credentials and no results without a job. Trusted lifts these caps up to its grant. Promote only a sensor you installed and whose pairing you verified. This is audited and every administrator is notified.'
              )
            : t(
                'confirm.sensor.demoteDesc',
                'The sensor goes back to passive work only (T0), with no credentials and no results without a job, from its next request.'
              )
        }
        confirmText={
          trustTarget === 'trusted'
            ? t('confirm.sensor.promote', 'Promote')
            : t('confirm.sensor.demote', 'Set back to New')
        }
        destructive={trustTarget === 'new'}
        isLoading={saving}
        handleConfirm={() => trustTarget && void changeTrust(trustTarget)}
      />

      {editOpen && (
        <SensorGrantEditDialog
          open={editOpen}
          onOpenChange={setEditOpen}
          sensorId={sensorId}
          grant={grant}
          onSaved={(next: SensorGrant) => mutate(next, { revalidate: false })}
          onConflict={() => mutate()}
        />
      )}
    </DetailSection>
  )
}
