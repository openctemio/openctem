'use client'

/**
 * The one frame every dashboard widget renders in: title, one control (a menu
 * of open the list, table or chart, how the figure is counted and the host's
 * own items; a lone item is a button),
 * freshness, and every state a widget can be in. Each frame is its own error
 * boundary, so one malformed payload never blanks the dashboard.
 */

import {
  Component,
  useCallback,
  useId,
  useMemo,
  useState,
  type ErrorInfo,
  type ReactNode,
} from 'react'
import {
  AlertCircle,
  BarChart3,
  Clock,
  Info,
  List,
  Lock,
  MoreHorizontal,
  Plug,
  RefreshCw,
  ShieldAlert,
  Table2,
  X,
} from 'lucide-react'
import Link from '@/components/link'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { errorDetails } from '@/lib/api/access-state'
import { describePermissionDenied } from '@/lib/api/permission-denied'
import {
  ageMs,
  formatAbsoluteTime,
  formatCount,
  formatDuration,
  formatRelativeTime,
} from '@/lib/format-metric'
import { safeInternalHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'
import type { SkeletonKind, WidgetState } from './types'
import { WidgetFrameContext, type WidgetBodyView } from './widget-frame-context'

export interface WidgetFrameProps {
  title: string
  /** Plain-words definition (formula, population, window): "How this is counted" in the menu. */
  definition?: ReactNode
  /** The list the figure counts, with the same filter: "Open list" in the menu. */
  listHref?: string
  /** The host's own items (an editor's Edit, Duplicate, Remove), after the frame's. */
  menuItems?: ActionMenuEntry[]
  /** False for a preview that cannot be operated: the frame then has no menu. */
  menu?: boolean
  /** When the figures were computed (ISO). Shown as "Updated …" with the absolute time on hover. */
  asOf?: string | null
  /** The page's own "Updated" time: a widget repeats its time only when stale or when it differs. */
  pageAsOf?: string | null
  state: WidgetState
  /** Skeleton shape while loading (default: chart). */
  skeleton?: SkeletonKind
  /** The figures, rendered for ready, stale and partial. */
  children?: ReactNode
  /** Retry for error and stale (omitted: no Retry button). */
  onRetry?: () => void
  /** Clear the filters that excluded everything (no_results). */
  onClearFilters?: () => void
  /** no_data_yet: what will appear here, and the next step. */
  emptyMessage?: string
  emptyAction?: { label: string; href: string }
  /** The list's real count, shown next to the title ("Findings 791"). */
  count?: number | null
  /** not_measured: why there is no figure ("Fewer than 5 fixed findings in 30 days"). */
  notMeasuredReason?: string
  /** no_access / module_off: the API error, whose details name the missing grant. */
  error?: unknown
  /** module_off: the module's name, and where an administrator turns it on. */
  moduleName?: string
  moduleHref?: string
  /** partial: what is missing ("Fixed findings could not be loaded"). */
  partialMessage?: string
  /** Extra controls in the header, before the menu. */
  actions?: ReactNode
  className?: string
}

const SKELETON_HEIGHT = 'min-h-[7rem]'

function WidgetSkeleton({ kind }: { kind: SkeletonKind }) {
  const { t } = useTranslation()
  const label = t('dashboardKit.state.loading', 'Loading')
  switch (kind) {
    case 'stat':
      return (
        <div
          className={cn('flex flex-col gap-2', SKELETON_HEIGHT)}
          role="status"
          aria-label={label}
        >
          <Skeleton className="h-8 w-24" />
          <Skeleton className="h-3 w-32" />
          <Skeleton className="mt-auto h-8 w-full" />
        </div>
      )
    case 'list':
      return (
        <div
          className={cn('flex flex-col gap-2', SKELETON_HEIGHT)}
          role="status"
          aria-label={label}
        >
          {[0, 1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-6 w-full" />
          ))}
        </div>
      )
    case 'grid':
      return (
        <div
          className={cn('grid grid-cols-4 gap-1', SKELETON_HEIGHT)}
          role="status"
          aria-label={label}
        >
          {Array.from({ length: 12 }, (_, i) => (
            <Skeleton key={i} className="h-7 w-full" />
          ))}
        </div>
      )
    case 'stages':
      return (
        <div
          className={cn('grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5', SKELETON_HEIGHT)}
          role="status"
          aria-label={label}
        >
          {[0, 1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-full w-full" />
          ))}
        </div>
      )
    default:
      return (
        <div
          className={cn('flex items-end gap-2', SKELETON_HEIGHT)}
          role="status"
          aria-label={label}
        >
          {[40, 70, 55, 85, 60, 75, 45].map((h, i) => (
            <Skeleton key={i} className="w-full" style={{ height: `${h}%` }} />
          ))}
        </div>
      )
  }
}

/** A centred message for the states that show no figures. */
function StateMessage({
  icon,
  title,
  body,
  children,
  tone = 'muted',
}: {
  icon: ReactNode
  title: string
  body?: string | null
  children?: ReactNode
  tone?: 'muted' | 'destructive'
}) {
  return (
    <div
      className={cn(
        'flex flex-1 flex-col items-center justify-center gap-1.5 py-4 text-center',
        SKELETON_HEIGHT
      )}
    >
      <span
        className={cn(
          '[&_svg]:size-5',
          tone === 'destructive' ? 'text-destructive' : 'text-muted-foreground'
        )}
        aria-hidden
      >
        {icon}
      </span>
      <p className="text-body font-medium">{title}</p>
      {body && <p className="max-w-xs text-cap text-muted-foreground">{body}</p>}
      {children}
    </div>
  )
}

function RetryButton({ onRetry }: { onRetry: () => void }) {
  const { t } = useTranslation()
  return (
    <Button variant="outline" size="sm" className="mt-1" onClick={onRetry}>
      <RefreshCw aria-hidden />
      {t('dashboardKit.action.retry', 'Retry')}
    </Button>
  )
}

function Freshness({ asOf, stale }: { asOf: string; stale: boolean }) {
  const { t, locale } = useTranslation()
  const age = ageMs(asOf)
  return (
    <p className="mt-auto flex flex-wrap items-center gap-2 pt-2 text-cap text-muted-foreground">
      <span title={formatAbsoluteTime(asOf, locale)}>
        {t('dashboardKit.freshness.updated', 'Updated {time}', {
          time: formatRelativeTime(asOf, locale),
        })}
      </span>
      {stale && (
        <span className="inline-flex items-center gap-1 font-medium text-warning">
          <Clock className="size-3.5" aria-hidden />
          {t('dashboardKit.freshness.stale', 'Stale for {age}', {
            age: age == null ? '—' : formatDuration(age / 3_600_000, locale),
          })}
        </span>
      )}
    </p>
  )
}

function FrameBody(props: WidgetFrameProps) {
  const { t } = useTranslation()
  const { state } = props
  switch (state) {
    case 'loading':
      return <WidgetSkeleton kind={props.skeleton ?? 'chart'} />
    case 'scope_changed':
      return (
        <div className="flex flex-col gap-2">
          <p className="flex items-center gap-1.5 text-cap text-muted-foreground" role="status">
            <ShieldAlert className="size-3.5" aria-hidden />
            {t('dashboardKit.state.scopeChanged', 'Your access changed. Updating these figures.')}
          </p>
          <WidgetSkeleton kind={props.skeleton ?? 'chart'} />
        </div>
      )
    case 'no_data_yet':
      return (
        <StateMessage
          icon={<Info />}
          title={t('dashboardKit.state.noDataYet', 'No data yet')}
          body={props.emptyMessage}
        >
          {props.emptyAction && safeInternalHref(props.emptyAction.href) && (
            <Button asChild variant="outline" size="sm" className="mt-1">
              <Link href={safeInternalHref(props.emptyAction.href) ?? '/'}>
                {props.emptyAction.label}
              </Link>
            </Button>
          )}
        </StateMessage>
      )
    case 'no_results':
      return (
        <StateMessage
          icon={<Info />}
          title={t('dashboardKit.state.noResults', 'Nothing matches these filters')}
        >
          {props.onClearFilters && (
            <Button variant="outline" size="sm" className="mt-1" onClick={props.onClearFilters}>
              {t('dashboardKit.action.clearFilters', 'Clear filters')}
            </Button>
          )}
        </StateMessage>
      )
    case 'not_measured':
      return (
        <div className={cn('flex flex-1 flex-col justify-center gap-1', SKELETON_HEIGHT)}>
          <p className="text-figure tabular-nums text-muted-foreground">—</p>
          <p className="text-cap text-muted-foreground">
            {props.notMeasuredReason ??
              t('dashboardKit.state.notMeasured', 'Not measured yet for this period')}
          </p>
        </div>
      )
    case 'no_access':
      return (
        <StateMessage
          icon={<Lock />}
          title={t('dashboardKit.state.noAccess', 'You do not have access to these figures')}
          body={
            describePermissionDenied(errorDetails(props.error)) ??
            t(
              'dashboardKit.state.noAccessHint',
              'Ask an organization administrator to grant access.'
            )
          }
        />
      )
    case 'module_off':
      return (
        <StateMessage
          icon={<Plug />}
          title={
            props.moduleName
              ? t('dashboardKit.state.moduleOffNamed', '{module} is turned off', {
                  module: props.moduleName,
                })
              : t('dashboardKit.state.moduleOff', 'This feature is turned off')
          }
          body={t(
            'dashboardKit.state.moduleOffHint',
            'An organization administrator can turn it on in Settings.'
          )}
        >
          {props.moduleHref && safeInternalHref(props.moduleHref) && (
            <Button asChild variant="outline" size="sm" className="mt-1">
              <Link href={safeInternalHref(props.moduleHref) ?? '/'}>
                {t('dashboardKit.action.openSettings', 'Open settings')}
              </Link>
            </Button>
          )}
        </StateMessage>
      )
    case 'error':
      return (
        <StateMessage
          icon={<AlertCircle />}
          tone="destructive"
          title={t('dashboardKit.state.error', "Couldn't load these figures")}
          body={t('dashboardKit.state.errorHint', 'The other widgets are not affected.')}
        >
          {props.onRetry && <RetryButton onRetry={props.onRetry} />}
        </StateMessage>
      )
    case 'partial':
      return (
        <>
          <p className="mb-2 flex items-center gap-1.5 text-cap text-warning" role="status">
            <AlertCircle className="size-3.5" aria-hidden />
            {props.partialMessage ??
              t('dashboardKit.state.partial', 'Some of these figures could not be loaded')}
          </p>
          {props.children}
        </>
      )
    default:
      return <>{props.children}</>
  }
}

interface BoundaryProps {
  children: ReactNode
  fallback: (reset: () => void) => ReactNode
}

/** Catches a render error inside one widget, so the rest of the dashboard keeps working. */
export class WidgetErrorBoundary extends Component<BoundaryProps, { failed: boolean }> {
  state = { failed: false }

  static getDerivedStateFromError() {
    return { failed: true }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    if (process.env.NODE_ENV !== 'production') {
      console.error('dashboard widget failed to render', error, info.componentStack)
    }
  }

  reset = () => this.setState({ failed: false })

  render() {
    if (this.state.failed) return this.props.fallback(this.reset)
    return this.props.children
  }
}

/**
 * The frame's one control. Two items or more are the shared action menu; a
 * single item is that action as a button (a menu never holds one item);
 * nothing applies, nothing is shown.
 */
function FrameMenu({
  title,
  label,
  items,
}: {
  title: string
  label: string
  items: ActionMenuEntry[]
}) {
  // The button is pulled into the frame's padding, so the title line keeps
  // its height; on a phone its touch area is 44 px.
  const className = '-my-1 -me-1.5 shrink-0 text-muted-foreground'
  if (items.length === 0) return null
  const only = items.length === 1 && items[0].kind !== 'sub' ? items[0] : null
  if (only) {
    const Icon = only.icon ?? MoreHorizontal
    const href = safeInternalHref(only.href)
    return href ? (
      <Button
        asChild
        variant="ghost"
        size="icon-sm"
        className={className}
        data-testid="widget-action"
      >
        <Link href={href} aria-label={only.label} title={only.label}>
          <Icon aria-hidden />
        </Link>
      </Button>
    ) : (
      <Button
        variant="ghost"
        size="icon-sm"
        className={className}
        aria-label={only.label}
        title={only.label}
        onClick={only.onSelect}
        data-testid="widget-action"
      >
        <Icon aria-hidden />
      </Button>
    )
  }
  return (
    <ActionMenu
      title={title}
      label={label}
      items={items}
      trigger={
        <Button
          variant="ghost"
          size="icon-sm"
          className={className}
          aria-label={label}
          data-testid="widget-menu"
        >
          <MoreHorizontal aria-hidden />
        </Button>
      }
    />
  )
}

export function WidgetFrame(props: WidgetFrameProps) {
  const { t, locale } = useTranslation()
  const titleId = useId()
  const noteId = useId()
  const { title, definition, asOf, state, actions, className, onRetry } = props
  const showsFigures = state === 'ready' || state === 'stale' || state === 'partial'

  // A chart with a table alternative registers here; the menu then offers the
  // other view, and the visualization draws the chosen one.
  const [initialView, setInitialView] = useState<WidgetBodyView | null>(null)
  const [chosenView, setChosenView] = useState<WidgetBodyView | null>(null)
  const registerViews = useCallback((initial: WidgetBodyView) => {
    setInitialView(initial)
    return () => setInitialView(null)
  }, [])
  const frame = useMemo(() => ({ view: chosenView, registerViews }), [chosenView, registerViews])
  const view = chosenView ?? initialView
  const [noteOpen, setNoteOpen] = useState(false)

  const listHref = showsFigures ? safeInternalHref(props.listHref) : undefined
  const items: ActionMenuEntry[] = []
  if (listHref)
    items.push({
      id: 'list',
      label: t('dashboardKit.action.openList', 'Open list'),
      icon: List,
      href: listHref,
    })
  if (showsFigures && view)
    items.push({
      id: 'view',
      label:
        view === 'chart'
          ? t('dashboardKit.action.showTable', 'Show table')
          : t('dashboardKit.action.showChart', 'Show chart'),
      icon: view === 'chart' ? Table2 : BarChart3,
      onSelect: () => setChosenView(view === 'chart' ? 'table' : 'chart'),
    })
  if (definition)
    items.push({
      id: 'definition',
      label: t('dashboardKit.action.definition', 'How this is counted'),
      icon: Info,
      onSelect: () => setNoteOpen((open) => !open),
    })
  for (const item of props.menuItems ?? []) items.push({ section: 'host', ...item })
  const menuLabel = t('dashboardKit.action.menu', 'Actions for {title}', { title })

  return (
    <section
      aria-labelledby={titleId}
      aria-busy={state === 'loading' || state === 'scope_changed'}
      data-state={state}
      data-view={showsFigures && view ? view : undefined}
      className={cn(
        'flex h-full min-w-0 flex-col overflow-hidden rounded-lg border bg-card p-4 text-card-foreground',
        className
      )}
    >
      <header className="mb-2 flex items-start gap-2">
        {/* A widget title is the level under the page title (h1): h2, so
            the sections inside a widget (h3) keep the heading order. */}
        <h2 id={titleId} className="min-w-0 flex-1 text-card-title line-clamp-2 sm:line-clamp-1">
          {title}
          {props.count != null && (
            <span
              className="ms-1.5 font-normal tabular-nums text-muted-foreground"
              data-testid="widget-count"
            >
              {formatCount(props.count, locale)}
            </span>
          )}
        </h2>
        {actions}
        {props.menu !== false && <FrameMenu title={title} label={menuLabel} items={items} />}
      </header>
      {noteOpen && definition && (
        <div
          id={noteId}
          role="status"
          data-testid="widget-definition"
          className="mb-2 flex items-start gap-2 rounded-md bg-muted px-3 py-2 text-cap text-muted-foreground"
        >
          <div className="min-w-0 flex-1">{definition}</div>
          <Button
            variant="ghost"
            size="xs"
            className="-me-1 shrink-0"
            aria-label={t('dashboardKit.action.closeDefinition', 'Close how this is counted')}
            onClick={() => setNoteOpen(false)}
          >
            <X aria-hidden />
          </Button>
        </div>
      )}
      <WidgetErrorBoundary
        fallback={(reset) => (
          <StateMessage
            icon={<AlertCircle />}
            tone="destructive"
            title={t('dashboardKit.state.error', "Couldn't load these figures")}
            body={t('dashboardKit.state.errorHint', 'The other widgets are not affected.')}
          >
            <RetryButton
              onRetry={() => {
                reset()
                onRetry?.()
              }}
            />
          </StateMessage>
        )}
      >
        <WidgetFrameContext.Provider value={frame}>
          <div className="flex min-h-0 flex-1 flex-col">
            <FrameBody {...props} />
          </div>
        </WidgetFrameContext.Provider>
      </WidgetErrorBoundary>
      {showsFigures && asOf && (state === 'stale' || asOf !== props.pageAsOf) && (
        <Freshness asOf={asOf} stale={state === 'stale'} />
      )}
    </section>
  )
}
