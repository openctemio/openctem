import type { PillTone } from '@/features/shared/components/tone-pill'
import type { ThreatIntelFeed, ThreatIntelFeedState } from '../types'

/** The translate function of useTranslation. */
export type Translate = (
  key: string,
  fallback: string,
  params?: Record<string, string | number>
) => string

export function feedName(source: string, t: Translate): string {
  switch (source) {
    case 'epss':
      return t('admin.ti.feed.epss', 'EPSS (exploit prediction scores)')
    case 'kev':
      return t('admin.ti.feed.kev', 'CISA KEV (known exploited vulnerabilities)')
    case 'vulnfeed':
      return t('admin.ti.feed.vulnfeed', 'Vulnerability bundles')
    default:
      return source
  }
}

export function sourceName(name: string, t: Translate): string {
  switch (name.toLowerCase()) {
    case 'nvd':
      return t('admin.ti.source.nvd', 'NVD')
    case 'cve':
    case 'cvelist':
      return t('admin.ti.source.cve', 'CVE List')
    case 'kev':
      return t('admin.ti.source.kev', 'CISA KEV')
    case 'epss':
      return t('admin.ti.source.epss', 'EPSS')
    case 'ghsa':
      return t('admin.ti.source.ghsa', 'GitHub advisories')
    case 'osv':
      return t('admin.ti.source.osv', 'OSV')
    default:
      return name
  }
}

export function stateTone(state: ThreatIntelFeedState): PillTone {
  switch (state) {
    case 'up_to_date':
      return 'success'
    case 'waiting_for_publisher':
    case 'running':
      return 'info'
    case 'stale':
    case 'failing':
      return 'warning'
    case 'refused':
      return 'destructive'
    default:
      return 'muted'
  }
}

export function stateLabel(state: ThreatIntelFeedState, t: Translate): string {
  switch (state) {
    case 'up_to_date':
      return t('admin.ti.state.up_to_date', 'Up to date')
    case 'waiting_for_publisher':
      return t('admin.ti.state.waiting_for_publisher', 'Waiting for the publisher')
    case 'stale':
      return t('admin.ti.state.stale', 'Stale')
    case 'failing':
      return t('admin.ti.state.failing', 'Failing')
    case 'refused':
      return t('admin.ti.state.refused', 'Refused')
    case 'running':
      return t('admin.ti.state.running', 'Running')
    default:
      return t('admin.ti.state.off', 'Off')
  }
}

/** A short duration: 20 min, 6 h, 3 d. */
export function formatSpan(seconds: number, t: Translate): string {
  if (seconds >= 86400 && seconds % 86400 === 0)
    return t('admin.ti.unit.d', '{n} d', { n: seconds / 86400 })
  if (seconds >= 3600) return t('admin.ti.unit.h', '{n} h', { n: Math.round(seconds / 3600) })
  return t('admin.ti.unit.min', '{n} min', { n: Math.max(1, Math.round(seconds / 60)) })
}

/** The tooltip of the state pill: how often the feed runs and when it goes stale. */
export function stateHint(f: ThreatIntelFeed, t: Translate): string {
  return t('admin.ti.hint', 'Runs every {interval}; stale after {stale}.', {
    interval: formatSpan(f.interval_seconds, t),
    stale: formatSpan(f.stale_after_seconds, t),
  })
}

export interface FeedProblem {
  message: string
  action: string
}

/**
 * The failure of a feed as an error code with an action. The raw server text
 * is never shown here; it sits behind the Details disclosure.
 */
export function feedProblem(f: ThreatIntelFeed, t: Translate): FeedProblem | null {
  if (!f.error_code || f.state === 'running' || f.state === 'up_to_date') return null
  const p = f.error_params ?? {}
  const host = p.host ?? ''
  switch (f.error_code) {
    case 'publisher_empty':
      return {
        message: t('admin.ti.error.publisher_empty', 'No bundle has been published yet.'),
        action: t(
          'admin.ti.action.publisher_empty',
          'Nothing to fix here. The first bundle appears when the collector publishes one.'
        ),
      }
    case 'unreachable':
      return {
        message: host
          ? t('admin.ti.error.unreachable', 'Cannot reach {host}.', { host })
          : t('admin.ti.error.unreachableNoHost', 'The source cannot be reached.'),
        action: t(
          'admin.ti.action.unreachable',
          'Allow outbound access to the source, set a mirror, or provide a bundle directory.'
        ),
      }
    case 'http_status':
      return {
        message: t('admin.ti.error.http_status', '{host} answered {status}.', {
          host: host || t('admin.ti.error.theSource', 'The source'),
          status: p.status ?? '',
        }),
        action:
          p.status === '403'
            ? t(
                'admin.ti.action.http_forbidden',
                'The source blocks this network. Check outbound access and mirrors.'
              )
            : t('admin.ti.action.http_retry', 'It is retried on the next run.'),
      }
    case 'signature_invalid':
      return {
        message: t(
          'admin.ti.error.signature_invalid',
          'A bundle was refused: its signature does not match the pinned root.'
        ),
        action: t(
          'admin.ti.action.signature_invalid',
          'Do not override. Check VULNFEED_ROOT_KEY_ID and report it to the security contact.'
        ),
      }
    case 'keyset_rollback':
    case 'sequence_rollback':
      return {
        message: t(
          'admin.ti.error.rollback',
          'A bundle older than the one applied was offered and refused.'
        ),
        action: t('admin.ti.action.rollback', 'Check the mirror: it may serve an old copy.'),
      }
    case 'expired':
      return {
        message: t('admin.ti.error.expired', 'The newest bundle has expired.'),
        action: t('admin.ti.action.expired', 'The publisher or a mirror stopped updating.'),
      }
    case 'bundle_invalid':
      return {
        message: t('admin.ti.error.bundle_invalid', 'A bundle was refused: it did not verify.'),
        action: t(
          'admin.ti.action.bundle_invalid',
          'Do not override. The next bundle is checked on the next run.'
        ),
      }
    case 'guard_refused':
      return {
        message:
          p.kind === 'removal'
            ? t(
                'admin.ti.error.guard_removal',
                'Refused: the bundle would remove {count} entries (limit {limit}).',
                { count: p.count ?? '', limit: p.limit ?? '' }
              )
            : t(
                'admin.ti.error.guard_snapshot',
                'Refused: the snapshot has {count} entries, below the minimum of {limit}.',
                { count: p.count ?? '', limit: p.limit ?? '' }
              ),
        action: t(
          'admin.ti.action.guard_refused',
          'Wait for the next update. The stored data is kept.'
        ),
      }
    case 'empty_feed':
      return {
        message: t(
          'admin.ti.error.empty_feed',
          'The source returned no entries. The stored data was kept.'
        ),
        action: t(
          'admin.ti.action.empty_feed',
          'It is retried on the next run. This is usually a change on the source side.'
        ),
      }
    case 'not_configured':
      return {
        message: t('admin.ti.error.not_configured', 'Bundle import is not configured.'),
        action: t('admin.ti.action.not_configured', 'Set VULNFEED_ROOT_KEY_ID.'),
      }
    case 'interrupted':
      return {
        message: t('admin.ti.error.interrupted', 'The last run did not finish.'),
        action: t('admin.ti.action.interrupted', 'It runs again on the next schedule.'),
      }
    default:
      return {
        message: t('admin.ti.error.failed', 'The last run failed.'),
        action: t('admin.ti.action.failed', 'Open the details for the server message.'),
      }
  }
}

/** Short form of a key id: SHA256:cb881872...a246c2 */
export function shortKeyId(id: string): string {
  return id.length > 24 ? `${id.slice(0, 14)}...${id.slice(-6)}` : id
}
