'use client'

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import type { AppliedIdentity, StepRun } from '@/lib/api/scan-workflow-types'
import { toDisplayText } from '@/lib/untrusted-text'

/** The steps that report what their requests were sent with. */
export function stepsWithSentWith(steps: StepRun[] | undefined): StepRun[] {
  return (steps ?? []).filter((s) => (s.sensor_settings?.sent_with?.length ?? 0) > 0)
}

function useSourceLabel() {
  const { t } = useTranslation()
  return (source?: string) => {
    switch (source) {
      case 'job':
        return t('scans.sentWith.src.job', 'Platform and organization')
      case 'job_locked':
        return t('scans.sentWith.src.jobLocked', 'Enforced or program')
      case 'sensor':
        return t('scans.sentWith.src.sensor', 'Sensor owner')
      default:
        return toDisplayText(source ?? '')
    }
  }
}

function AppliedIdentityView({ a }: { a: AppliedIdentity }) {
  const { t } = useTranslation()
  const sourceLabel = useSourceLabel()
  return (
    <div className="space-y-2 rounded-md border p-3 text-sm" data-testid="sent-with-entry">
      <div className="flex flex-wrap items-center gap-2">
        {a.tool && <span className="font-medium">{toDisplayText(a.tool)}</span>}
        {a.required && (
          <Badge variant="secondary">
            {t('scans.sentWith.required', 'Identification required')}
          </Badge>
        )}
        {a.carrier && (
          <span className="text-muted-foreground">
            {a.carrier === 'forwarder'
              ? t('scans.sentWith.carrierForwarder', 'Added by the sensor forwarder')
              : t('scans.sentWith.carrierTool', 'Sent by the tool')}
          </span>
        )}
      </div>
      {a.user_agent && (
        <div>
          <span className="text-muted-foreground">{t('scans.sentWith.ua', 'User-Agent')}: </span>
          <span className="font-mono break-all">{toDisplayText(a.user_agent)}</span>
          {a.user_agent_source && (
            <span className="text-muted-foreground"> ({sourceLabel(a.user_agent_source)})</span>
          )}
          {(a.user_agent_pool ?? 0) > 1 && (
            <span className="block text-muted-foreground">
              {t('scans.sentWith.rotating', 'Rotating over {n} values, one per target host', {
                n: a.user_agent_pool ?? 0,
              })}
            </span>
          )}
          {a.user_agent_reason && (
            <span className="block text-muted-foreground">
              {toDisplayText(a.user_agent_reason)}
            </span>
          )}
        </div>
      )}
      {(a.headers?.length ?? 0) > 0 && (
        <ul className="space-y-1">
          {a.headers?.map((h, i) => (
            <li key={`${h.name}-${i}`} className="flex flex-wrap items-center gap-2">
              <span
                className={h.applied ? 'font-mono' : 'font-mono text-muted-foreground line-through'}
              >
                {toDisplayText(h.name)}: {toDisplayText(h.value)}
              </span>
              {h.source && <Badge variant="outline">{sourceLabel(h.source)}</Badge>}
              {!h.applied && (
                <span className="text-muted-foreground">
                  {t('scans.sentWith.notApplied', 'Not sent')}
                  {h.reason ? `: ${toDisplayText(h.reason)}` : ''}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
      {a.query && (
        <div>
          <span className="text-muted-foreground">
            {t('scans.sentWith.query', 'Query parameter')}:{' '}
          </span>
          <span
            className={
              a.query.applied ? 'font-mono' : 'font-mono text-muted-foreground line-through'
            }
          >
            ?{toDisplayText(a.query.name)}={toDisplayText(a.query.value)}
          </span>
          {!a.query.applied && (
            <span className="text-muted-foreground">
              {' '}
              {t('scans.sentWith.notApplied', 'Not sent')}
              {a.query.reason ? `: ${toDisplayText(a.query.reason)}` : ''}
            </span>
          )}
        </div>
      )}
    </div>
  )
}

/**
 * Run detail "Sent with": per step, what its requests carried as the sensor
 * reported it (User-Agent, identification headers and query parameter, with
 * their source and why one was not sent). Sensor-supplied: shown as text only.
 */
export function RunSentWith({ steps }: { steps: StepRun[] }) {
  return (
    <div className="space-y-4" data-testid="run-sent-with">
      {steps.map((s) => (
        <div key={s.id} className="space-y-2">
          <p className="text-sm font-medium">{toDisplayText(s.step_name || s.step_key)}</p>
          {s.sensor_settings?.sent_with?.map((a, i) => (
            <AppliedIdentityView key={i} a={a} />
          ))}
        </div>
      ))}
    </div>
  )
}
