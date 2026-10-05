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

import { TARGET_NETWORK_LABELS, formatGrantList, profileLabel, tierLabel } from '../lib/grant'
import { SensorGrantEditDialog } from './sensor-grant-edit-dialog'

/** The message to show for a failed grant change; a 409 also reloads. */
export function grantErrorMessage(err: unknown): string {
  if (err instanceof ApiClientError || (err && typeof err === 'object' && 'statusCode' in err)) {
    const e = err as { statusCode?: number; message?: string }
    if (e.statusCode === 409)
      return 'The grant changed since you opened it. It was reloaded; review it and try again.'
    if ((e.statusCode === 403 || e.statusCode === 400) && e.message) return e.message
  }
  return 'Could not change the grant'
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
  if (!granted) return <>Not allowed</>
  if (effective === false) return <>Allowed by the grant · off while the sensor is New</>
  return <>Allowed</>
}

export function TrustBadge({ level }: { level: string }) {
  return level === 'trusted' ? (
    <Badge variant="secondary">Trusted</Badge>
  ) : (
    <Badge variant="outline" className="border-warning text-warning">
      New
    </Badge>
  )
}

export function SensorGrantSection({ sensorId }: { sensorId: string }) {
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
  const [saving, setSaving] = useState(false)

  if (!canRead) return null
  if (error) {
    return (
      <DetailSection title="Grant" icon={ShieldCheck}>
        <p className="text-sm text-muted-foreground">The grant could not be loaded.</p>
      </DetailSection>
    )
  }
  if (!grant) return null

  const eff = grant.effective
  const isNew = grant.trust_level !== 'trusted'

  const changeTrust = async (to: 'trusted' | 'new') => {
    setSaving(true)
    try {
      const next = await updateSensorGrant(sensorId, grantUpdateRequest(grant, { trust_level: to }))
      await mutate(next, { revalidate: false })
      toast.success(to === 'trusted' ? 'Sensor promoted to Trusted' : 'Sensor set back to New')
      setTrustTarget(null)
    } catch (err) {
      toast.error(grantErrorMessage(err))
      if (isVersionConflict(err)) await mutate()
    } finally {
      setSaving(false)
    }
  }

  const scope =
    grant.target_cidrs === null && grant.target_domains === null
      ? 'Any'
      : [...(grant.target_cidrs ?? []), ...(grant.target_domains ?? [])].join(', ') || 'None'

  return (
    <DetailSection
      title="Grant"
      icon={ShieldCheck}
      actions={
        (canNarrow || canWiden) && (
          <Button variant="outline" size="sm" onClick={() => setEditOpen(true)}>
            <Pencil className="h-3.5 w-3.5" />
            {grant.legacy_broad ? 'Narrow' : 'Edit'}
          </Button>
        )
      }
    >
      {grant.legacy_broad && (
        <div data-testid="legacy-broad-warning">
          <DetailCallout tone="warning" icon={AlertTriangle} title="Legacy broad grant: narrow it">
            This sensor existed before per-sensor grants and may still do anything a sensor can: any
            job, intrusive tiers, credentials and results without a job. Pick the profile that
            matches what it does.
          </DetailCallout>
        </div>
      )}

      <dl className="space-y-1.5" data-testid="sensor-grant">
        <Row label="Profile">{profileLabel(grant.profile)}</Row>
        <Row label="Trust level">
          <span className="inline-flex flex-wrap items-center gap-2">
            <TrustBadge level={grant.trust_level} />
            {isNew && canWiden && (
              <Button size="sm" variant="outline" onClick={() => setTrustTarget('trusted')}>
                Promote to Trusted
              </Button>
            )}
            {!isNew && canNarrow && (
              <Button size="sm" variant="ghost" onClick={() => setTrustTarget('new')}>
                Set back to New
              </Button>
            )}
          </span>
        </Row>
        <Row label="Job types">{formatGrantList(grant.job_types)}</Row>
        <Row label="Zones">{formatGrantList(grant.zone_ids, zoneName)}</Row>
        <Row label="Tools">{formatGrantList(grant.tools)}</Row>
        <Row label="Capabilities">{formatGrantList(grant.capabilities)}</Row>
        <Row label="Tier ceiling">
          {tierLabel(grant.tier_ceiling)}
          {eff && eff.tier_ceiling < grant.tier_ceiling && (
            <span className="text-muted-foreground">
              {' '}
              · {tierLabel(eff.tier_ceiling)} while New
            </span>
          )}
        </Row>
        <Row label="Target network">
          {TARGET_NETWORK_LABELS[grant.target_network] ?? grant.target_network}
        </Row>
        <Row label="Target scope">{scope}</Row>
        <Row label="Credentials">
          <Flag granted={grant.allow_credentials} effective={eff?.allow_credentials} />
        </Row>
        <Row label="Results without a job">
          <Flag granted={grant.allow_push_ingest} effective={eff?.allow_push_ingest} />
        </Row>
        <Row label="Remote actions">
          pause, drain{grant.remote_actions?.length ? `, ${grant.remote_actions.join(', ')}` : ''}
        </Row>
      </dl>

      <ConfirmDialog
        open={trustTarget !== null}
        onOpenChange={(o) => !o && setTrustTarget(null)}
        title={
          trustTarget === 'trusted'
            ? 'Promote this sensor to Trusted?'
            : 'Set this sensor back to New?'
        }
        desc={
          trustTarget === 'trusted'
            ? 'A New sensor gets passive work only (T0), no credentials and no results without a job. Trusted lifts these caps up to its grant. Promote only a sensor you installed and whose pairing you verified. This is audited and every administrator is notified.'
            : 'The sensor goes back to passive work only (T0), with no credentials and no results without a job, from its next request.'
        }
        confirmText={trustTarget === 'trusted' ? 'Promote' : 'Set back to New'}
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
