'use client'

/**
 * One page change with its diff (RFC-138). Every value comes from the fetched
 * page, which the target controls: it is shown as plain text (control and
 * bidi characters made visible), never as a link, markup or markdown.
 */

import { AlertTriangle, FileCode2, FileText, Link2, Minus, Plus } from 'lucide-react'
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import {
  DetailCallout,
  DetailField,
  DetailFieldGrid,
  DetailSection,
  DetailSections,
  DetailSheetHeader,
  ErrorState,
  RelativeTime,
  SeverityBadge,
  SheetDetailToolbar,
} from '@/features/shared'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import { toSeverity } from './easm-overview'
import { usePageChange, type PageScriptRef } from '../hooks/use-page-monitor'

/** A value from the fetched page as one safe line of text. */
export function Untrusted({ value, className }: { value: string; className?: string }) {
  return (
    <span dir="ltr" className={cn('break-all font-mono text-xs [unicode-bidi:isolate]', className)}>
      {toDisplayText(value, 600)}
    </span>
  )
}

export function formatBytes(n: number, locale: string): string {
  const fmt = new Intl.NumberFormat(locale, { maximumFractionDigits: 1 })
  if (n < 1024) return `${fmt.format(n)} B`
  if (n < 1024 * 1024) return `${fmt.format(n / 1024)} KiB`
  return `${fmt.format(n / (1024 * 1024))} MiB`
}

function ScriptList({ scripts, testId }: { scripts: PageScriptRef[]; testId: string }) {
  const { t } = useTranslation()
  return (
    <ul className="space-y-2" data-testid={testId}>
      {scripts.map((s) => (
        <li key={s.id} className="flex flex-wrap items-center gap-2">
          {s.inline ? (
            <span className="text-sm text-muted-foreground">
              {t('pageMonitor.diff.inlineScript', 'Inline script')}
            </span>
          ) : (
            <Untrusted value={s.src ?? s.id} />
          )}
          {s.third_party && (
            <Badge variant="outline">{t('pageMonitor.diff.thirdParty', 'Third party')}</Badge>
          )}
          {s.third_party && !s.integrity && (
            <Badge variant="outline">
              {t('pageMonitor.diff.noIntegrity', 'No integrity check')}
            </Badge>
          )}
        </li>
      ))}
    </ul>
  )
}

function LineList({ lines, sign }: { lines: string[]; sign: 'added' | 'removed' }) {
  const Icon = sign === 'added' ? Plus : Minus
  return (
    <ul className="space-y-1" data-testid={`diff-lines-${sign}`}>
      {lines.map((l, i) => (
        <li
          key={`${i}-${l}`}
          className={cn(
            'flex items-start gap-2 rounded-sm px-2 py-1',
            sign === 'added' ? 'bg-success/10' : 'bg-destructive/10'
          )}
        >
          <Icon
            className={cn(
              'mt-0.5 h-3 w-3 shrink-0',
              sign === 'added' ? 'text-success' : 'text-destructive'
            )}
            aria-label={sign}
          />
          <Untrusted value={l} />
        </li>
      ))}
    </ul>
  )
}

export function PageChangeSheet({
  changeId,
  onClose,
}: {
  changeId: string | null
  onClose: () => void
}) {
  const { t, locale } = useTranslation()
  const { change, error, isLoading } = usePageChange(changeId)
  const d = change?.diff
  const title = t('pageMonitor.diff.title', 'Page change')
  return (
    <Sheet open={changeId !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent side="right" showCloseButton={false} className="w-full sm:max-w-2xl">
        <SheetHeader className="block p-0 sm:p-0">
          <SheetTitle className="sr-only">{title}</SheetTitle>
          <SheetDescription className="sr-only">
            {t(
              'pageMonitor.diff.description',
              'What changed on the watched URL since the fetch before.'
            )}
          </SheetDescription>
          <SheetDetailToolbar title={title} onClose={onClose} />
        </SheetHeader>
        <SheetBody className="p-0">
          {error ? (
            <div className="p-6">
              <ErrorState title={t('pageMonitor.diff.what', 'the page change')} error={error} />
            </div>
          ) : isLoading || !change || !d ? (
            <div className="space-y-3 p-6" aria-hidden>
              <Skeleton className="h-6 w-2/3" />
              <Skeleton className="h-24 w-full" />
            </div>
          ) : (
            <div className="pb-6" data-testid="page-change-sheet">
              <DetailSheetHeader
                icon={d.kind === 'script' ? FileCode2 : FileText}
                title={<Untrusted value={change.url} className="text-sm font-semibold" />}
                subtitle={
                  change.parent_url ? (
                    <span className="flex flex-wrap gap-1">
                      {t('pageMonitor.loadedBy', 'Loaded by')}{' '}
                      <Untrusted value={change.parent_url} />
                    </span>
                  ) : undefined
                }
                status={<SeverityBadge severity={toSeverity(change.severity)} />}
                badges={
                  <>
                    <Badge variant="secondary" className="font-normal">
                      <RelativeTime date={change.detected_at} />
                    </Badge>
                    {change.muted && (
                      <Badge variant="outline">{t('pageMonitor.muted', 'Muted')}</Badge>
                    )}
                  </>
                }
              />
              <DetailSections className="space-y-6 px-4 sm:px-6">
                {(d.new_third_party_hosts?.length ?? 0) > 0 && (
                  <DetailCallout
                    tone="destructive"
                    icon={AlertTriangle}
                    title={t(
                      'pageMonitor.diff.newHostsTitle',
                      'The page loads scripts from a new third-party host'
                    )}
                    label={t(
                      'pageMonitor.diff.newHostsTitle',
                      'The page loads scripts from a new third-party host'
                    )}
                  >
                    <p className="mb-2">
                      {t(
                        'pageMonitor.diff.newHostsBody',
                        'A script from a host the page did not use before can read everything typed on it. Check that it was added on purpose.'
                      )}
                    </p>
                    <ul className="space-y-1" data-testid="diff-new-hosts">
                      {d.new_third_party_hosts?.map((h) => (
                        <li key={h}>
                          <Untrusted value={h} />
                        </li>
                      ))}
                    </ul>
                  </DetailCallout>
                )}
                {(d.scripts_added?.length ?? 0) > 0 && (
                  <DetailSection
                    title={t('pageMonitor.diff.scriptsAdded', 'Scripts added')}
                    count={d.scripts_added?.length}
                  >
                    <ScriptList scripts={d.scripts_added ?? []} testId="diff-scripts-added" />
                  </DetailSection>
                )}
                {(d.scripts_removed?.length ?? 0) > 0 && (
                  <DetailSection
                    title={t('pageMonitor.diff.scriptsRemoved', 'Scripts removed')}
                    count={d.scripts_removed?.length}
                  >
                    <ScriptList scripts={d.scripts_removed ?? []} testId="diff-scripts-removed" />
                  </DetailSection>
                )}
                {d.hash_to && (
                  <DetailSection title={t('pageMonitor.diff.content', 'Content')} icon={FileCode2}>
                    <DetailFieldGrid>
                      <DetailField label={t('pageMonitor.diff.sizeBefore', 'Size before')}>
                        {formatBytes(d.size_from, locale)}
                      </DetailField>
                      <DetailField label={t('pageMonitor.diff.sizeAfter', 'Size after')}>
                        {formatBytes(d.size_to, locale)}
                      </DetailField>
                      <DetailField label={t('pageMonitor.diff.hashBefore', 'SHA-256 before')} full>
                        <Untrusted value={d.hash_from ?? ''} />
                      </DetailField>
                      <DetailField label={t('pageMonitor.diff.hashAfter', 'SHA-256 after')} full>
                        <Untrusted value={d.hash_to} />
                      </DetailField>
                    </DetailFieldGrid>
                  </DetailSection>
                )}
                {(d.urls_added?.length ?? 0) > 0 && (
                  <DetailSection
                    title={t('pageMonitor.diff.urlsAdded', 'New URLs in the script')}
                    icon={Link2}
                    count={d.urls_added?.length}
                  >
                    <LineList lines={d.urls_added ?? []} sign="added" />
                  </DetailSection>
                )}
                {(d.urls_removed?.length ?? 0) > 0 && (
                  <DetailSection
                    title={t('pageMonitor.diff.urlsRemoved', 'URLs no longer in the script')}
                    count={d.urls_removed?.length}
                  >
                    <LineList lines={d.urls_removed ?? []} sign="removed" />
                  </DetailSection>
                )}
                {((d.lines_added?.length ?? 0) > 0 || (d.lines_removed?.length ?? 0) > 0) && (
                  <DetailSection title={t('pageMonitor.diff.text', 'Page text')} icon={FileText}>
                    <div className="space-y-3">
                      {(d.lines_added?.length ?? 0) > 0 && (
                        <LineList lines={d.lines_added ?? []} sign="added" />
                      )}
                      {(d.lines_removed?.length ?? 0) > 0 && (
                        <LineList lines={d.lines_removed ?? []} sign="removed" />
                      )}
                    </div>
                  </DetailSection>
                )}
                {d.truncated && (
                  <p className="text-xs text-muted-foreground">
                    {t(
                      'pageMonitor.diff.truncated',
                      'Long lists are cut at 100 items and text at 200 lines.'
                    )}
                  </p>
                )}
              </DetailSections>
            </div>
          )}
        </SheetBody>
      </SheetContent>
    </Sheet>
  )
}
