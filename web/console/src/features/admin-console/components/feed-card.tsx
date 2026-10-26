'use client'

import type { ReactNode } from 'react'
import { ChevronDown, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Switch } from '@/components/ui/switch'
import { RelativeTime } from '@/features/shared'
import { TonePill } from '@/features/shared/components/tone-pill'
import { useTranslation } from '@/context/i18n-provider'
import { feedName, feedProblem, stateHint, stateLabel, stateTone } from '../lib/feed-status'
import type { ThreatIntelFeed } from '../types'

interface FeedCardProps {
  feed: ThreatIntelFeed
  canWrite: boolean
  /** Another action is in flight. */
  busy: boolean
  onSync: () => void
  onToggle: (on: boolean) => void
  /** Feed-specific rows and tables (the bundle feed's sequence and sources). */
  children?: ReactNode
  className?: string
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 tabular-nums">{children}</dd>
    </>
  )
}

/**
 * One intelligence feed: the server-computed state, the failure as an error
 * code with an action (the raw server text behind Details), honest times and
 * the two sizes (stored catalog, written by the last run). Every feed uses
 * this card.
 */
export function FeedCard({
  feed,
  canWrite,
  busy,
  onSync,
  onToggle,
  children,
  className,
}: FeedCardProps) {
  const { t } = useTranslation()
  const problem = feedProblem(feed, t)
  const running = feed.state === 'running'
  const never = t('admin.ti.neverRun', 'Never')

  return (
    <Card className={className} data-feed={feed.source} data-state={feed.state}>
      <CardHeader className="flex flex-row items-start justify-between gap-3 space-y-0">
        <div className="min-w-0 space-y-1.5">
          <CardTitle className="text-base">{feedName(feed.source, t)}</CardTitle>
          <TonePill
            tone={stateTone(feed.state)}
            label={stateLabel(feed.state, t)}
            title={stateHint(feed, t)}
            state={feed.state}
          />
        </div>
        <Switch
          checked={feed.enabled}
          disabled={!canWrite || busy}
          aria-label={t('admin.ti.toggle', 'Scheduled sync for {feed}', {
            feed: feedName(feed.source, t),
          })}
          onCheckedChange={onToggle}
        />
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        {problem && (
          <div className="space-y-0.5" role="status">
            <p className="font-medium break-words">{problem.message}</p>
            <p className="text-muted-foreground">{problem.action}</p>
            {feed.state === 'failing' && feed.failing_since && (
              <p className="text-muted-foreground">
                {t('admin.ti.failingSince', 'Failing since')}{' '}
                <RelativeTime date={feed.failing_since} />
              </p>
            )}
          </div>
        )}
        {children}
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
          <Row label={t('admin.ti.dataAsOf', 'Data as of')}>
            {feed.data_as_of ? <RelativeTime date={feed.data_as_of} /> : never}
          </Row>
          <Row label={t('admin.ti.catalog', 'In the catalog')}>
            {feed.catalog_records.toLocaleString()}
          </Row>
          <Row label={t('admin.ti.changed', 'Changed in the last run')}>
            {feed.records_changed.toLocaleString()}
          </Row>
          <Row label={t('admin.ti.lastAttempt', 'Last attempt')}>
            {feed.last_attempt_at ? <RelativeTime date={feed.last_attempt_at} /> : never}
          </Row>
          <Row label={t('admin.ti.lastSuccess', 'Last success')}>
            {feed.last_success_at ? <RelativeTime date={feed.last_success_at} /> : never}
          </Row>
          <Row label={t('admin.ti.nextRun', 'Next run')}>
            {feed.next_run_at ? (
              <RelativeTime date={feed.next_run_at} />
            ) : (
              t('admin.ti.notScheduled', 'Not scheduled')
            )}
          </Row>
        </dl>
        <div className="flex flex-wrap items-center gap-2">
          {canWrite && (
            <Button size="sm" variant="outline" disabled={busy || running} onClick={onSync}>
              <RefreshCw className={running ? 'me-2 size-4 animate-spin' : 'me-2 size-4'} />
              {running ? t('admin.ti.running', 'Running') : t('admin.ti.syncOne', 'Sync now')}
            </Button>
          )}
          {feed.last_error && problem && (
            <Collapsible className="w-full">
              <CollapsibleTrigger asChild>
                <Button size="sm" variant="ghost" className="-ms-2">
                  <ChevronDown className="me-1 size-4" />
                  {t('admin.ti.details', 'Details')}
                </Button>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <pre className="mt-1 max-h-40 overflow-auto rounded-md bg-muted p-2 text-xs break-words whitespace-pre-wrap">
                  {feed.last_error}
                </pre>
              </CollapsibleContent>
            </Collapsible>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
