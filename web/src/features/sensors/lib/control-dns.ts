import type { SensorConfigCheck, SensorConfigReport } from '@/lib/api/sensor-types'

import { msg } from './content'
import type { Tr } from './format'
import type { HealthIssue } from './health-issues'

/**
 * The control channel's DNS as the sensor reports it (config check
 * runtime.control_dns): whether the platform host name failed to resolve,
 * and when. Only what the sensor reported; the platform never guesses a
 * cause for a missing heartbeat.
 */
export type ControlDnsFact =
  | { kind: 'failing'; cached: boolean; cause?: string; since?: Date }
  | { kind: 'recovered'; failedAt?: Date; recoveredAt?: Date }

export const CONTROL_DNS_CHECK = 'runtime.control_dns'

const CAUSES = ['timeout', 'not_found', 'server_misbehaving', 'temporary', 'other'] as const

function observed(c: SensorConfigCheck, label: string): string | undefined {
  return c.observed?.find((o) => o.label === label)?.value
}

/** A unix-seconds parameter as a date; undefined when absent or not a number. */
export function unixParam(v: string | undefined): Date | undefined {
  if (!v || !/^\d{1,12}$/.test(v)) return undefined
  const d = new Date(Number(v) * 1000)
  return Number.isNaN(d.getTime()) ? undefined : d
}

const TIME_PARAMS = new Set(['since', 'resolved_at', 'failed_at', 'recovered_at'])

/**
 * An observed value as shown: the DNS check's unix-seconds times as local
 * date and time, every other value unchanged.
 */
export function observedValueText(checkId: string, label: string, value: string): string {
  if (checkId !== CONTROL_DNS_CHECK || !TIME_PARAMS.has(label)) return value
  return unixParam(value)?.toLocaleString() ?? value
}

export function controlDnsFact(report?: SensorConfigReport | null): ControlDnsFact | null {
  const c = report?.checks?.find((x) => x.id === CONTROL_DNS_CHECK)
  if (!c) return null
  const cause = observed(c, 'cause')
  switch (c.code) {
    case 'cached_address':
    case 'lookup_failed':
      return {
        kind: 'failing',
        cached: c.code === 'cached_address',
        cause: cause && (CAUSES as readonly string[]).includes(cause) ? cause : undefined,
        since: unixParam(observed(c, 'since')),
      }
    case 'recovered':
      return {
        kind: 'recovered',
        failedAt: unixParam(observed(c, 'failed_at')),
        recoveredAt: unixParam(observed(c, 'recovered_at')),
      }
  }
  return null
}

/** The lookup error class in words. */
export function dnsCauseText(cause: string | undefined, tr?: Tr): string {
  switch (cause) {
    case 'timeout':
      return msg(tr, 'sensors.dns.cause.timeout', 'the resolver did not answer')
    case 'not_found':
      return msg(tr, 'sensors.dns.cause.not_found', 'the name was not found')
    case 'server_misbehaving':
      return msg(tr, 'sensors.dns.cause.server_misbehaving', 'the resolver failed the query')
    case 'temporary':
      return msg(tr, 'sensors.dns.cause.temporary', 'a temporary resolver failure')
    default:
      return msg(tr, 'sensors.dns.cause.other', 'a resolver error')
  }
}

/**
 * The heartbeat issue of a sensor that stopped heartbeating, with the DNS
 * failure it last reported as the reason. Other issues are unchanged.
 */
export function withControlDnsReason(
  issues: HealthIssue[],
  fact: ControlDnsFact | null,
  tr?: Tr
): HealthIssue[] {
  if (fact?.kind !== 'failing') return issues
  return issues.map((i) =>
    i.key !== 'heartbeat'
      ? i
      : {
          ...i,
          title: msg(tr, 'sensors.dns.offlineTitle', 'Offline: DNS failure'),
          text: `${i.text} ${msg(
            tr,
            'sensors.dns.offlineText',
            'Its last report said the platform host name does not resolve ({cause}). Pin the platform host on the sensor (extra_hosts), check its resolver, and keep the DNS server out of intrusive scans.',
            { cause: dnsCauseText(fact.cause, tr) }
          )}`,
          since: fact.since ? fact.since.toISOString() : i.since,
        }
  )
}
