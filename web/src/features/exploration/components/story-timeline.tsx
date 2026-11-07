'use client'

/**
 * How we found this (api docs/architecture/exploration.md): the story of a
 * finding or an asset as a compact timeline, scope entry first and the
 * subject last. Each step names what it did (in scope by, found under,
 * discovered by, scanned by, reported by), links to its record and shows
 * when. A step the viewer may not see reads "A step you cannot see" with no
 * name or link. One component for every surface that shows a story (the
 * finding page, the asset page and the asset sheet).
 */

import type { ReactNode } from 'react'
import { ArrowDown, Crosshair, EyeOff, Inbox, Radar, ShieldAlert } from 'lucide-react'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { SignalChip } from '@/components/ui/signal-chip'
import { useTranslation } from '@/context/i18n-provider'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { MetaLine } from '@/features/shared/components/text-layout'
import { AssetTypeIcon, getAssetTypeLabel } from '@/features/assets/lib/asset-type-icon'
import { discoverySourceLabel, lineageEdgeLabel } from '@/features/assets/lib/asset-lineage'
import { sightingChannelLabel } from '@/features/findings/components/detail/finding-seen-by'
import { cn } from '@/lib/utils'
import { hiddenHint, stepHref, stepRoleLabel, type Story, type StoryStep } from '../lib/story'

const linkClass = 'break-all underline-offset-2 hover:underline'

function StepIcon({ step }: { step: StoryStep }) {
  const subject = step.kind === 'finding' || !!step.asset?.subject
  const Icon =
    step.kind === 'scope_entry'
      ? Crosshair
      : step.kind === 'scan'
        ? Radar
        : step.kind === 'report'
          ? Inbox
          : step.kind === 'finding'
            ? ShieldAlert
            : null
  return (
    <span
      aria-hidden
      className={cn(
        'flex h-6 w-6 shrink-0 items-center justify-center rounded-full',
        step.hidden
          ? 'bg-muted text-muted-foreground'
          : subject
            ? 'bg-primary text-primary-foreground'
            : 'bg-muted text-muted-foreground'
      )}
    >
      {step.hidden ? (
        <EyeOff className="h-3.5 w-3.5" />
      ) : Icon ? (
        <Icon className="h-3.5 w-3.5" />
      ) : (
        <AssetTypeIcon type={step.asset?.type ?? ''} className="h-3.5 w-3.5" />
      )}
    </span>
  )
}

/** The step's name: what to click. */
function StepName({ step }: { step: StoryStep }) {
  const { t } = useTranslation()
  let name: ReactNode = null
  if (step.scope_entry) {
    name = <span className="font-mono text-meta">{step.scope_entry.pattern}</span>
  } else if (step.asset) {
    name = step.asset.name
  } else if (step.scan) {
    name = step.scan.scan_name || t('exploration.story.scanRun', 'Scan run')
  } else if (step.report) {
    name = sightingChannelLabel(t, step.report.channel)
  } else if (step.finding) {
    name = step.finding.title
  }
  const href = stepHref(step)
  if (!href) return <span className="break-all font-medium">{name}</span>
  return (
    <Link href={href} className={cn('font-medium', linkClass)}>
      {name}
    </Link>
  )
}

/** The step's details on one meta line. */
function stepMeta(t: ReturnType<typeof useTranslation>['t'], step: StoryStep): ReactNode[] {
  const meta: ReactNode[] = []
  if (step.asset) {
    if (step.asset.type) meta.push(<span key="type">{getAssetTypeLabel(step.asset.type)}</span>)
    if (step.asset.discovery_source)
      meta.push(<span key="src">{discoverySourceLabel(t, step.asset.discovery_source)}</span>)
    if (step.asset.discovery_tool)
      meta.push(<SignalChip key="tool">{step.asset.discovery_tool}</SignalChip>)
  }
  if (step.scope_entry?.excluded_by) {
    meta.push(
      <span key="excl" className="text-destructive">
        {t('exploration.story.excludedBy', 'Excluded by {pattern}', {
          pattern: step.scope_entry.excluded_by,
        })}
      </span>
    )
  }
  if (step.scan) {
    if (step.scan.step_name) meta.push(<span key="step">{step.scan.step_name}</span>)
    if (step.scan.capability)
      meta.push(
        <span key="cap" className="font-mono">
          {step.scan.capability}
        </span>
      )
    if (step.scan.tool) meta.push(<SignalChip key="tool">{step.scan.tool}</SignalChip>)
    if (step.scan.relation)
      meta.push(<span key="rel">{lineageEdgeLabel(t, step.scan.relation)}</span>)
  }
  if (step.report) {
    const r = step.report
    if (r.tool)
      meta.push(
        <SignalChip key="tool">
          {r.tool_version ? `${r.tool} ${r.tool_version}` : r.tool}
        </SignalChip>
      )
    if (r.sensor?.id) meta.push(<span key="sensor">{r.sensor.name || r.sensor.id}</span>)
    else if (r.sender && r.sender !== 'platform')
      meta.push(
        <span key="sender" className="font-mono" dir="auto">
          {r.sender}
        </span>
      )
    meta.push(
      <span key="count">
        {t('exploration.story.seenCount', '{count, plural, one {# time} other {# times}}', {
          count: r.seen_count ?? 1,
        })}
      </span>
    )
    if (r.backfilled)
      meta.push(
        <Badge key="bf" variant="outline" className="text-xs font-normal">
          {t('findings.seenBy.backfilled', 'From earlier records')}
        </Badge>
      )
  }
  if (step.at) meta.push(<RelativeTime key="at" date={step.at} />)
  return meta
}

function StepRow({ step }: { step: StoryStep }) {
  const { t } = useTranslation()
  if (step.hidden) {
    return (
      <div
        className="flex items-center gap-2 text-muted-foreground"
        title={hiddenHint(t, step.kind)}
      >
        <StepIcon step={step} />
        <span>{stepRoleLabel(t, step)}</span>
      </div>
    )
  }
  return (
    <div className="flex items-start gap-2">
      <StepIcon step={step} />
      <div className="min-w-0 flex-1">
        <div className="flex min-w-0 flex-wrap items-baseline gap-x-2">
          <span className="text-meta text-muted-foreground">{stepRoleLabel(t, step)}</span>
          <StepName step={step} />
        </div>
        <MetaLine items={stepMeta(t, step)} className="mt-0.5" />
      </div>
    </div>
  )
}

/** The story's chain as an ordered list; render inside a section. */
export function StoryTimeline({ story, className }: { story: Story; className?: string }) {
  const { t } = useTranslation()
  const steps = story.steps
  return (
    <div className={cn('space-y-2 text-sm', className)}>
      <ol
        className="space-y-1"
        aria-label={t('exploration.story.chainLabel', 'How we found this')}
        data-testid="story-timeline"
      >
        {story.truncated && (
          <li className="text-xs text-muted-foreground">
            {t('exploration.story.truncated', 'Earlier steps are not shown.')}
          </li>
        )}
        {steps.map((step, i) => {
          // Between two assets, how the upper one leads to the lower one.
          const prev = i > 0 ? steps[i - 1] : undefined
          const edge = prev?.kind === 'asset' && step.kind === 'asset' ? prev.asset?.via : undefined
          return (
            <li key={i} className="space-y-1" data-kind={step.kind} data-hidden={step.hidden}>
              {edge && (
                <div className="flex items-center gap-2 ps-1.5 text-xs text-muted-foreground">
                  <ArrowDown className="h-3 w-3 shrink-0" aria-hidden />
                  <span>{lineageEdgeLabel(t, edge)}</span>
                </div>
              )}
              <StepRow step={step} />
            </li>
          )
        })}
      </ol>
      {story.more_reports > 0 && (
        <p className="text-xs text-muted-foreground">
          {t(
            'exploration.story.moreReports',
            '{count, plural, one {# more source reported it} other {# more sources reported it}}: see Seen by.',
            { count: story.more_reports }
          )}
        </p>
      )}
    </div>
  )
}
