'use client'

import { RelativeTime } from '@/features/shared'
import { TonePill } from '@/features/shared/components/tone-pill'
import { useTranslation } from '@/context/i18n-provider'
import { shortKeyId, sourceName } from '../lib/feed-status'
import type { ThreatIntelFeed } from '../types'

/**
 * What only the vulnerability bundle feed has: the applied sequence, when it
 * was published, whether its signature verified, and how fresh each upstream
 * source it carries is, as one list of facts.
 */
export function BundleDetail({ feed }: { feed: ThreatIntelFeed }) {
  const { t } = useTranslation()
  const d = feed.detail
  if (!d) return null
  const none = t('admin.ti.none', 'None yet')
  const verified = d.applied_sequence > 0 && feed.state !== 'refused'
  return (
    <div className="space-y-3">
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
        <dt className="text-muted-foreground">{t('admin.ti.sequence', 'Applied sequence')}</dt>
        <dd className="tabular-nums">{d.applied_sequence > 0 ? d.applied_sequence : none}</dd>
        <dt className="text-muted-foreground">{t('admin.ti.published', 'Published')}</dt>
        <dd>{d.bundle_created_at ? <RelativeTime date={d.bundle_created_at} /> : none}</dd>
        <dt className="text-muted-foreground">{t('admin.ti.signature', 'Signature')}</dt>
        <dd className="min-w-0 break-words">
          {verified
            ? t('admin.ti.signatureVerified', 'Verified (key set v{version}, root {root})', {
                version: d.keyset_version,
                root: d.root_key_id ? shortKeyId(d.root_key_id) : '',
              })
            : feed.state === 'refused'
              ? t('admin.ti.signatureRefused', 'A bundle was refused')
              : t('admin.ti.signatureNone', 'Nothing to verify yet')}
        </dd>
      </dl>
      {/* Each upstream source on a line of its own: its name, how old its
          data is and whether that is fresh. The same facts list as above, not
          a table inside the card. */}
      {d.sources.length > 0 && (
        <dl
          data-testid="bundle-sources"
          aria-label={t('admin.ti.sourcesLabel', 'Sources in the bundle')}
          className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1"
        >
          {d.sources.map((s) => (
            <div key={s.name} className="contents">
              <dt className="text-muted-foreground">{sourceName(s.name, t)}</dt>
              <dd className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
                <span>
                  {t('admin.ti.dataAsOf', 'Data as of')}{' '}
                  {s.as_of ? <RelativeTime date={s.as_of} /> : none}
                </span>
                <TonePill
                  tone={s.fresh ? 'success' : 'warning'}
                  label={
                    s.fresh ? t('admin.ti.fresh', 'Fresh') : t('admin.ti.staleSource', 'Stale')
                  }
                />
              </dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  )
}
