'use client'

/**
 * The path tree of a web origin, desktop form: one row per node (a path
 * segment), children loaded when a node opens, so a 5,000-endpoint origin
 * never ships its whole list. Each row shows how many endpoints lie under the
 * node and, when findings sit there, how many with a dot in the colour of the
 * worst one. Out-of-scope nodes stay listed with a mark: a path exclusion
 * never hides a path.
 *
 * It follows the tree pattern: one tab stop (roving tabindex), arrows move,
 * Right opens or enters, Left closes or goes up, Enter and Space select,
 * Home and End jump. Rows have one fixed height, so nothing moves when a
 * level's counts arrive.
 */

import { useCallback, useRef, useState, type KeyboardEvent } from 'react'
import { Braces, ChevronRight, CircleSlash, Folder, Globe } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { SEVERITY_DOT_COLORS } from '@/lib/severity-colors'
import { cn } from '@/lib/utils'
import { useWebPaths, type WebPathFolder } from '../api/use-web-paths'
import { pathTrail, type PathFilters } from '../lib/web-paths-url'

const SEVERITY_DOT: Record<string, string> = {
  critical: SEVERITY_DOT_COLORS.critical,
  high: SEVERITY_DOT_COLORS.high,
}

/** The severity mark of a node: a dot for a critical or high finding under it. */
export function SeverityDot({ severity, className }: { severity?: string; className?: string }) {
  const { t } = useTranslation()
  const tone = severity ? SEVERITY_DOT[severity] : undefined
  if (!tone || !severity)
    return <span aria-hidden className={cn('inline-block size-2', className)} />
  return (
    <span
      className={cn('inline-block size-2 shrink-0 rounded-full', tone, className)}
      role="img"
      aria-label={t(
        `attackSurface.paths.severityUnder.${severity}`,
        `${severity} finding under it`
      )}
    />
  )
}

/** The counts at a row's end, in fixed-width cells. */
export function NodeCounts({
  endpoints,
  findings,
  severity,
  outOfScope,
}: {
  endpoints: number
  findings: number
  severity?: string
  outOfScope: number
}) {
  const { t } = useTranslation()
  return (
    <span className="ms-auto flex shrink-0 items-center gap-2 text-xs text-muted-foreground tabular-nums">
      {outOfScope > 0 && (
        <CircleSlash
          className="size-3.5 text-warning"
          role="img"
          aria-label={t('attackSurface.paths.outOfScopeCount', '{count} out of scope', {
            count: outOfScope,
          })}
        />
      )}
      <span
        className="min-w-7 text-end"
        title={t(
          'attackSurface.paths.endpointsCount',
          '{count, plural, one {# endpoint} other {# endpoints}}',
          { count: endpoints }
        )}
      >
        {endpoints}
      </span>
      <span
        className="inline-flex min-w-9 items-center justify-end gap-1"
        title={t(
          'attackSurface.paths.findingsCount',
          '{count, plural, one {# open finding} other {# open findings}}',
          { count: findings }
        )}
      >
        {findings > 0 ? (
          <>
            <SeverityDot severity={severity} />
            <span className="text-foreground">{findings}</span>
          </>
        ) : null}
      </span>
    </span>
  )
}

interface TreeProps {
  assetId: string
  filters: PathFilters
  selected: string
  onSelect: (path: string) => void
  /** The root row's totals (the origin as a whole). */
  rootLabel: string
  rootEndpoints: number
  rootFindings: number
  rootSeverity?: string
}

function moveFocus(
  tree: HTMLElement | null,
  from: HTMLElement,
  to: 'next' | 'prev' | 'first' | 'last'
) {
  if (!tree) return
  const items = Array.from(tree.querySelectorAll<HTMLElement>('[role="treeitem"]'))
  const i = items.indexOf(from)
  const target =
    to === 'first'
      ? items[0]
      : to === 'last'
        ? items[items.length - 1]
        : items[to === 'next' ? Math.min(i + 1, items.length - 1) : Math.max(i - 1, 0)]
  target?.focus()
}

export function PathTree({
  assetId,
  filters,
  selected,
  onSelect,
  rootLabel,
  rootEndpoints,
  rootFindings,
  rootSeverity,
}: TreeProps) {
  const { t } = useTranslation()
  const treeRef = useRef<HTMLUListElement>(null)
  // The selected node's ancestors start open, so a shared link shows its place.
  const [open, setOpen] = useState<Set<string>>(
    () => new Set(['/', ...pathTrail(selected).map((n) => n.path)])
  )
  const toggle = useCallback((path: string, next?: boolean) => {
    setOpen((prev) => {
      const s = new Set(prev)
      const want = next ?? !s.has(path)
      if (want) s.add(path)
      else s.delete(path)
      return s
    })
  }, [])

  const onKey = (
    e: KeyboardEvent<HTMLElement>,
    path: string,
    expandable: boolean,
    parent: string | null
  ) => {
    const el = e.currentTarget
    switch (e.key) {
      case 'ArrowDown':
        moveFocus(treeRef.current, el, 'next')
        break
      case 'ArrowUp':
        moveFocus(treeRef.current, el, 'prev')
        break
      case 'Home':
        moveFocus(treeRef.current, el, 'first')
        break
      case 'End':
        moveFocus(treeRef.current, el, 'last')
        break
      case 'ArrowRight':
        if (!expandable) return
        if (!open.has(path)) toggle(path, true)
        else moveFocus(treeRef.current, el, 'next')
        break
      case 'ArrowLeft':
        if (expandable && open.has(path)) toggle(path, false)
        else if (parent !== null)
          treeRef.current
            ?.querySelector<HTMLElement>(`[role="treeitem"][data-path="${CSS.escape(parent)}"]`)
            ?.focus()
        break
      case 'Enter':
      case ' ':
        onSelect(path)
        break
      default:
        return
    }
    e.preventDefault()
    e.stopPropagation()
  }

  return (
    <ul
      ref={treeRef}
      role="tree"
      aria-label={t('attackSurface.paths.treeLabel', 'Paths of this site')}
      className="min-w-0 py-1"
      data-testid="path-tree"
    >
      <li
        role="treeitem"
        aria-level={1}
        aria-expanded={open.has('/')}
        aria-selected={selected === '/'}
        data-path="/"
        tabIndex={selected === '/' ? 0 : -1}
        onKeyDown={(e) => onKey(e, '/', true, null)}
        className="outline-none"
      >
        <NodeRow
          depth={0}
          name={rootLabel}
          icon="root"
          expandable
          isOpen={open.has('/')}
          isSelected={selected === '/'}
          onToggle={() => toggle('/')}
          onSelect={() => onSelect('/')}
          endpoints={rootEndpoints}
          findings={rootFindings}
          severity={rootSeverity}
          outOfScope={0}
        />
        {open.has('/') && (
          <TreeLevel
            assetId={assetId}
            path="/"
            depth={1}
            filters={filters}
            selected={selected}
            open={open}
            onToggle={toggle}
            onSelect={onSelect}
            onKey={onKey}
          />
        )}
      </li>
    </ul>
  )
}

interface LevelProps {
  assetId: string
  path: string
  depth: number
  filters: PathFilters
  selected: string
  open: Set<string>
  onToggle: (path: string, next?: boolean) => void
  onSelect: (path: string) => void
  onKey: (
    e: KeyboardEvent<HTMLElement>,
    path: string,
    expandable: boolean,
    parent: string | null
  ) => void
}

function TreeLevel({
  assetId,
  path,
  depth,
  filters,
  selected,
  open,
  onToggle,
  onSelect,
  onKey,
}: LevelProps) {
  const { t } = useTranslation()
  const { data, error, isLoading } = useWebPaths(assetId, path, filters, { perPage: 0 })
  if (!data && isLoading) {
    return (
      <ul role="group" aria-busy="true">
        {[0, 1].map((i) => (
          <li
            key={i}
            className="flex h-8 items-center"
            style={{ paddingInlineStart: `${depth * 1}rem` }}
          >
            <Skeleton className="ms-7 h-3 w-24" />
          </li>
        ))}
      </ul>
    )
  }
  if (error && !data) {
    return (
      <p
        className="h-8 truncate text-xs text-muted-foreground"
        style={{ paddingInlineStart: `${depth + 1.75}rem` }}
      >
        {t('attackSurface.paths.levelFailed', 'Could not load this level.')}
      </p>
    )
  }
  const folders = data?.folders ?? []
  return (
    <ul role="group">
      {folders.map((f) => (
        <TreeNode
          key={f.path}
          folder={f}
          depth={depth}
          assetId={assetId}
          filters={filters}
          selected={selected}
          open={open}
          onToggle={onToggle}
          onSelect={onSelect}
          onKey={onKey}
          parent={path}
        />
      ))}
      {data?.folders_truncated && (
        <li
          className="flex h-8 items-center text-xs text-muted-foreground"
          style={{ paddingInlineStart: `${depth + 1.75}rem` }}
        >
          {t('attackSurface.paths.moreFolders', 'More paths: search to narrow')}
        </li>
      )}
    </ul>
  )
}

function TreeNode({
  folder,
  depth,
  parent,
  ...rest
}: Omit<LevelProps, 'path'> & { folder: WebPathFolder; parent: string }) {
  const { open, selected, onToggle, onSelect, onKey } = rest
  const isOpen = open.has(folder.path)
  const isSelected = selected === folder.path
  return (
    <li
      role="treeitem"
      aria-level={depth + 1}
      aria-expanded={folder.has_folders ? isOpen : undefined}
      aria-selected={isSelected}
      data-path={folder.path}
      tabIndex={isSelected ? 0 : -1}
      onKeyDown={(e) => onKey(e, folder.path, folder.has_folders, parent)}
      className="outline-none"
    >
      <NodeRow
        depth={depth}
        name={folder.name}
        icon={folder.param ? 'param' : 'folder'}
        expandable={folder.has_folders}
        isOpen={isOpen}
        isSelected={isSelected}
        onToggle={() => onToggle(folder.path)}
        onSelect={() => onSelect(folder.path)}
        endpoints={folder.endpoints}
        findings={folder.findings}
        severity={folder.top_severity}
        outOfScope={folder.out_of_scope}
      />
      {folder.has_folders && isOpen && <TreeLevel {...rest} path={folder.path} depth={depth + 1} />}
    </li>
  )
}

function NodeRow({
  depth,
  name,
  icon,
  expandable,
  isOpen,
  isSelected,
  onToggle,
  onSelect,
  endpoints,
  findings,
  severity,
  outOfScope,
}: {
  depth: number
  name: string
  icon: 'root' | 'folder' | 'param'
  expandable: boolean
  isOpen: boolean
  isSelected: boolean
  onToggle: () => void
  onSelect: () => void
  endpoints: number
  findings: number
  severity?: string
  outOfScope: number
}) {
  const { t } = useTranslation()
  const Icon = icon === 'root' ? Globe : icon === 'param' ? Braces : Folder
  return (
    // The row is a pointer target only; the treeitem holds focus and keys.
    <div
      onClick={onSelect}
      className={cn(
        'flex h-8 cursor-pointer items-center gap-1.5 rounded-md pe-2 text-sm',
        'hover:bg-muted [[role=treeitem]:focus-visible>&]:ring-2 [[role=treeitem]:focus-visible>&]:ring-ring',
        isSelected && 'bg-accent font-medium text-accent-foreground'
      )}
      style={{ paddingInlineStart: `${depth}rem` }}
    >
      {expandable ? (
        <button
          type="button"
          tabIndex={-1}
          aria-hidden
          onClick={(e) => {
            e.stopPropagation()
            onToggle()
          }}
          className="grid size-6 shrink-0 place-items-center rounded text-muted-foreground hover:text-foreground"
          title={
            isOpen
              ? t('attackSurface.paths.collapse', 'Close')
              : t('attackSurface.paths.expand', 'Open')
          }
        >
          <ChevronRight className={cn('size-3.5 transition-transform', isOpen && 'rotate-90')} />
        </button>
      ) : (
        <span aria-hidden className="size-6 shrink-0" />
      )}
      <Icon
        aria-hidden
        className={cn(
          'size-3.5 shrink-0',
          icon === 'param' ? 'text-primary' : 'text-muted-foreground'
        )}
      />
      <span
        className={cn('min-w-0 truncate', icon !== 'root' && 'font-mono text-dense')}
        title={name}
      >
        {icon === 'param' ? (
          <>
            <span className="sr-only">
              {t('attackSurface.paths.paramNode', 'Variable segment')}{' '}
            </span>
            {name}
          </>
        ) : (
          name
        )}
      </span>
      <NodeCounts
        endpoints={endpoints}
        findings={findings}
        severity={severity}
        outOfScope={outOfScope}
      />
    </div>
  )
}
