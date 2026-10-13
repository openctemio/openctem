'use client'

/**
 * The suggested grant of a sensor (api docs/architecture/sensor-pairing.md,
 * "Leaving the legacy grant"): the narrowest profile that admitted every job
 * of the last 30 days, never wider than the current grant, applied in one
 * click. The server re-computes the suggestion on apply, asks for step-up
 * (the API client opens the re-authentication dialog) and answers 409 when
 * it changed; the card only shows what it read.
 */

import { useState } from 'react'
import { Sparkles } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { DetailCallout } from '@/features/shared'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import {
  applySensorGrantSuggestion,
  useSensorGrantSuggestion,
  type SensorGrant,
  type SensorGrantSuggestion,
} from '@/lib/api/sensor-grant-hooks'

import { profileLabel, tierLabel } from '../lib/grant'

type T = ReturnType<typeof useTranslation>['t']

/** One line per fact of the window, as people read it. */
export function usageLines(s: SensorGrantSuggestion, t: T): string[] {
  const u = s.usage
  if (u.job_count === 0 && !u.push_ingest) {
    return [t('sensors.grant.suggestion.usage.idle', 'No jobs and no results without a job.')]
  }
  const lines = [
    t('sensors.grant.suggestion.usage.jobs', '{count} jobs: {types}', {
      count: u.job_count,
      types: u.job_types.join(', ') || '-',
    }),
  ]
  if (u.tools.length) {
    lines.push(
      t('sensors.grant.suggestion.usage.tools', 'Tools: {tools}', { tools: u.tools.join(', ') })
    )
  }
  if (u.job_count > 0) {
    lines.push(
      t('sensors.grant.suggestion.usage.maxTier', 'Highest tier: {tier}', {
        tier: tierLabel(u.max_tier),
      })
    )
  }
  if (u.private_targets) {
    lines.push(t('sensors.grant.suggestion.usage.private', 'Private network targets'))
  } else if (u.public_targets) {
    lines.push(t('sensors.grant.suggestion.usage.publicOnly', 'Public targets only'))
  }
  if (u.zone_count > 0) {
    lines.push(
      t('sensors.grant.suggestion.usage.zones', 'Ran in {count} zones', { count: u.zone_count })
    )
  }
  if (u.push_ingest) {
    lines.push(t('sensors.grant.suggestion.usage.push', 'Sent results without a job'))
  }
  return lines
}

export function SensorGrantSuggestionCard({
  sensorId,
  legacyBroad,
  onApplied,
}: {
  sensorId: string
  /** The sensor is still on legacy-broad: say so when no profile fits. */
  legacyBroad: boolean
  /** Called with the stored grant after an apply. */
  onApplied: (next: SensorGrant) => void
}) {
  const { t } = useTranslation()
  const { data: s, mutate } = useSensorGrantSuggestion(sensorId)
  const [confirm, setConfirm] = useState(false)
  const [saving, setSaving] = useState(false)

  if (!s) return null

  const apply = async () => {
    setSaving(true)
    try {
      const next = await applySensorGrantSuggestion(sensorId, {
        version: s.current_version,
        profile: s.profile,
      })
      onApplied(next)
      toast.success(
        t('sensors.grant.suggestion.applied', 'Grant narrowed to {profile}', {
          profile: profileLabel(next.profile),
        })
      )
      setConfirm(false)
      await mutate()
    } catch (err) {
      const e = err as { statusCode?: number; message?: string }
      if (e?.statusCode === 409) {
        toast.error(
          t(
            'sensors.grant.suggestion.changed',
            'The suggestion changed since it was shown. It was reloaded; review it and try again.'
          )
        )
        await mutate()
      } else {
        toast.error(
          e?.statusCode === 403 && e.message
            ? e.message
            : t('sensors.grant.suggestion.error', 'Could not apply the suggested grant')
        )
      }
    } finally {
      setSaving(false)
    }
  }

  const windowText = t('sensors.grant.suggestion.window', 'Based on the last {days} days', {
    days: s.window_days,
  })

  if (!s.available) {
    // Nothing to apply: say why only when it helps the administrator.
    if (!legacyBroad || (s.reason !== 'no_profile_fits' && s.reason !== 'usage_incomplete'))
      return null
    return (
      <div data-testid="grant-suggestion" data-available="false">
        <DetailCallout
          tone="info"
          icon={Sparkles}
          title={t('sensors.grant.suggestion.noneTitle', 'No narrower profile fits')}
        >
          <p>
            {s.reason === 'usage_incomplete'
              ? t(
                  'sensors.grant.suggestion.incomplete',
                  'This sensor ran too many different jobs to check them all. Pick its profile with Narrow.'
                )
              : t(
                  'sensors.grant.suggestion.noFit',
                  'No profile admits every job this sensor ran without widening its grant (for example an intrusive T2 job). Narrow it by hand with Narrow.'
                )}
          </p>
          <p className="mt-1 text-muted-foreground">{windowText}</p>
        </DetailCallout>
      </div>
    )
  }

  const profile = profileLabel(s.profile)
  return (
    <div data-testid="grant-suggestion" data-available="true">
      <DetailCallout
        tone="info"
        icon={Sparkles}
        title={t('sensors.grant.suggestion.title', 'Suggested grant: {profile}', { profile })}
      >
        <p>
          {s.reason === 'no_activity'
            ? t(
                'sensors.grant.suggestion.idleBody',
                'This sensor did nothing in the window. The default profile of its kind is suggested.'
              )
            : t(
                'sensors.grant.suggestion.body',
                'The narrowest profile that admits every job this sensor ran. It is never wider than the current grant; the trust level is kept.'
              )}
        </p>
        <p className="mt-1 text-muted-foreground">{windowText}</p>
        <ul
          className="mt-1 list-disc pl-5 text-muted-foreground"
          data-testid="grant-suggestion-usage"
        >
          {usageLines(s, t).map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
        {s.changed.length > 0 && (
          <p className="mt-1 text-muted-foreground">
            {t('sensors.grant.suggestion.narrows', 'Narrows: {dims}', {
              dims: s.changed.join(', '),
            })}
          </p>
        )}
        <Button size="sm" className="mt-2" onClick={() => setConfirm(true)} disabled={saving}>
          {t('sensors.grant.suggestion.apply', 'Apply suggested grant')}
        </Button>
      </DetailCallout>

      <ConfirmDialog
        open={confirm}
        onOpenChange={setConfirm}
        title={t('sensors.grant.suggestion.confirmTitle', 'Apply the {profile} grant?', {
          profile,
        })}
        desc={t(
          'sensors.grant.suggestion.confirmDesc',
          'From its next request the sensor gets only the jobs this profile admits. A job outside it (for example a schedule that did not run in the window) is refused and named in the sensor timeline. You may be asked to confirm your identity. This is audited.'
        )}
        confirmText={t('sensors.grant.suggestion.confirm', 'Apply')}
        isLoading={saving}
        handleConfirm={() => void apply()}
      />
    </div>
  )
}
