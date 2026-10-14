'use client'

/**
 * How one asset property value is shown (research/129 §3.3). Every value
 * is scanner- or connector-supplied text: it is rendered as React text,
 * links go through `SafeExternalLink` / the inventory route, and JSON goes
 * through `JSON.stringify` into a text node.
 *
 * - a scalar: text; a boolean: Yes / No; an ISO timestamp or a key of
 *   format `expiry`: the local date with the relative time;
 * - registry formats: `ip` links to the IP asset, `url` is a safe external
 *   link, `code` is mono with a copy button;
 * - a list of scalars: every value, wrapped;
 * - a list of objects of one shape (DNS records, open ports, listeners): a
 *   compact table, columns in a known order;
 * - an object: a nested label/value list;
 * - anything deeper or mixed: pretty-printed JSON in a collapsible block.
 */

import * as React from 'react'
import { Check, ChevronRight, Copy } from 'lucide-react'
import Link from '@/components/link'
import { SafeExternalLink } from '@/components/safe-external-link'
import { RelativeTime } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { copyToClipboard } from '@/lib/clipboard'
import { cn } from '@/lib/utils'
import { humanizePropertyKey } from '@/features/asset-types/lib/property-schema'
import type { AssetPropertyFormat } from '@/features/asset-types/registry.generated'
import { serializeInventoryFilters } from '../lib/inventory-url'

type Scalar = string | number | boolean

/** Rows of a structured table shown before "Show all". */
const TABLE_ROWS = 10

/** Column order for tables of records; other keys follow in first-seen order. */
const COLUMN_ORDER = [
  'type',
  'name',
  'value',
  'data',
  'port',
  'protocol',
  'transport',
  'service',
  'product',
  'version',
  'state',
  'priority',
  'ttl',
]

const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$/

function isScalar(v: unknown): v is Scalar {
  return typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** True when `s` is an ISO-8601 date-time a scanner or connector wrote. */
export function isIsoTimestamp(s: string): boolean {
  return ISO_TIMESTAMP.test(s) && !Number.isNaN(Date.parse(s))
}

/**
 * The columns of a list that renders as a table, or null when it does not
 * (not a list of flat objects). Known record keys come first, in
 * `COLUMN_ORDER`; the rest keep the order they first appear in.
 */
export function recordColumns(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length === 0) return null
  if (!value.every((row) => isPlainObject(row))) return null
  const keys: string[] = []
  for (const row of value as Record<string, unknown>[]) {
    for (const [k, v] of Object.entries(row)) {
      // A nested value inside a record means the list is not a flat table.
      if (v !== null && v !== undefined && !isScalar(v)) {
        if (!(Array.isArray(v) && v.every(isScalar))) return null
      }
      if (!keys.includes(k)) keys.push(k)
    }
  }
  const rank = (k: string) => {
    const i = COLUMN_ORDER.indexOf(k.toLowerCase())
    return i === -1 ? COLUMN_ORDER.length : i
  }
  return keys
    .map((k, i) => [k, i] as const)
    .sort((a, b) => rank(a[0]) - rank(b[0]) || a[1] - b[1])
    .map(([k]) => k)
}

/** Whether a value has anything to show (null, '', [] and {} do not). */
export function hasPropertyValue(value: unknown): boolean {
  if (value === null || value === undefined || value === '') return false
  if (Array.isArray(value)) return value.length > 0
  if (isPlainObject(value)) return Object.keys(value).length > 0
  return true
}

function ipAssetHref(ip: string): string {
  return `/assets?${serializeInventoryFilters({ types: ['ip_address'], search: ip }).toString()}`
}

export function CopyValueButton({ text, className }: { text: string; className?: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = React.useState(false)
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation()
        void copyToClipboard(text).then((ok) => setCopied(ok))
      }}
      aria-label={t('assets.properties.copy', 'Copy value')}
      title={t('assets.properties.copy', 'Copy value')}
      className={cn(
        'inline-flex h-5 w-5 shrink-0 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        className
      )}
    >
      {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
    </button>
  )
}

function DateValue({ iso }: { iso: string }) {
  return (
    <span className="inline-flex flex-wrap items-baseline gap-x-1.5">
      <span>{new Date(iso).toLocaleString()}</span>
      <RelativeTime date={iso} className="text-xs" />
    </span>
  )
}

function ScalarValue({ value, format }: { value: Scalar; format?: AssetPropertyFormat }) {
  const { t } = useTranslation()
  if (typeof value === 'boolean') {
    return <>{value ? t('assets.properties.yes', 'Yes') : t('assets.properties.no', 'No')}</>
  }
  const text = String(value)
  if (typeof value === 'string' && (format === 'expiry' || isIsoTimestamp(text))) {
    if (!Number.isNaN(Date.parse(text))) return <DateValue iso={text} />
  }
  switch (format) {
    case 'ip':
      return (
        <Link href={ipAssetHref(text)} className="font-mono text-xs text-primary hover:underline">
          {text}
        </Link>
      )
    case 'url':
      return (
        <SafeExternalLink href={text} className="break-all text-primary hover:underline">
          {text}
        </SafeExternalLink>
      )
    case 'code':
      return (
        <span className="inline-flex max-w-full items-start gap-1">
          <code className="font-mono text-xs break-all">{text}</code>
          <CopyValueButton text={text} />
        </span>
      )
    default:
      return <>{text}</>
  }
}

function ColumnLabel({ name }: { name: string }) {
  const { t } = useTranslation()
  return <>{t(`assets.properties.columns.${name.toLowerCase()}`, humanizePropertyKey(name))}</>
}

function cellText(v: unknown): string {
  if (v === null || v === undefined || v === '') return ''
  if (Array.isArray(v)) return v.map(String).join(', ')
  return String(v)
}

/** A list of flat records (DNS records, open ports …) as a compact table. */
export function RecordTable({
  rows,
  columns,
  className,
}: {
  rows: Record<string, unknown>[]
  columns: string[]
  className?: string
}) {
  const { t } = useTranslation()
  const [all, setAll] = React.useState(false)
  const shown = all ? rows : rows.slice(0, TABLE_ROWS)
  return (
    <div className={cn('min-w-0 space-y-1.5', className)}>
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full text-xs">
          <thead className="bg-muted/50 text-muted-foreground">
            <tr>
              {columns.map((c) => (
                <th
                  key={c}
                  scope="col"
                  className="px-2 py-1.5 text-start font-medium whitespace-nowrap"
                >
                  <ColumnLabel name={c} />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((row, i) => (
              <tr key={i} className="border-t align-top">
                {columns.map((c) => (
                  <td key={c} className="px-2 py-1.5 font-mono break-all">
                    {cellText(row[c])}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length > TABLE_ROWS && (
        <button
          type="button"
          className="text-xs text-primary hover:underline"
          onClick={() => setAll((v) => !v)}
        >
          {all
            ? t('assets.properties.showFewer', 'Show fewer')
            : t('assets.properties.showAllRows', 'Show all {count}', { count: rows.length })}
        </button>
      )}
    </div>
  )
}

/** Pretty-printed JSON in a collapsible block, with a copy button. */
export function JsonBlock({
  value,
  defaultOpen = false,
}: {
  value: unknown
  defaultOpen?: boolean
}) {
  const { t } = useTranslation()
  const [open, setOpen] = React.useState(defaultOpen)
  const text = React.useMemo(() => JSON.stringify(value, null, 2), [value])
  const lines = text.split('\n').length
  return (
    <div className="min-w-0 space-y-1">
      <div className="flex items-center gap-1">
        <button
          type="button"
          aria-expanded={open}
          onClick={() => setOpen((v) => !v)}
          className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
        >
          <ChevronRight className={cn('h-3.5 w-3.5 transition-transform', open && 'rotate-90')} />
          {open
            ? t('assets.properties.hideJson', 'Hide JSON')
            : t('assets.properties.showJson', 'Show JSON ({count} lines)', { count: lines })}
        </button>
        <CopyValueButton text={text} />
      </div>
      {open && (
        <pre className="max-h-80 overflow-auto rounded-md border bg-muted/40 p-2 font-mono text-xs whitespace-pre-wrap break-all">
          {text}
        </pre>
      )}
    </div>
  )
}

function ObjectValue({ value, depth }: { value: Record<string, unknown>; depth: number }) {
  const entries = Object.entries(value).filter(([, v]) => hasPropertyValue(v))
  return (
    <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-sm">
      {entries.map(([k, v]) => (
        <React.Fragment key={k}>
          <dt className="text-xs leading-5 text-muted-foreground">
            <ColumnLabel name={k} />
          </dt>
          <dd className="min-w-0 break-words">
            <PropertyValue value={v} depth={depth + 1} />
          </dd>
        </React.Fragment>
      ))}
    </dl>
  )
}

export interface PropertyValueProps {
  value: unknown
  /** The registry display format of the key, when it has one. */
  format?: AssetPropertyFormat
  /** Nesting level; deep values fall back to the JSON block. */
  depth?: number
}

/** One property value, rendered by shape (see the file comment). */
export function PropertyValue({ value, format, depth = 0 }: PropertyValueProps) {
  if (!hasPropertyValue(value)) return null
  if (isScalar(value)) return <ScalarValue value={value} format={format} />
  if (Array.isArray(value)) {
    if (value.every(isScalar)) {
      // Plain words read best as one comma list; addresses, links and codes
      // each get their own wrapped item.
      if (!format && !value.some((v) => typeof v === 'string' && isIsoTimestamp(v))) {
        return <span className="break-words">{value.map(String).join(', ')}</span>
      }
      return (
        <span className="flex flex-wrap gap-x-3 gap-y-1">
          {value.map((v, i) => (
            <span key={`${String(v)}-${i}`} className={cn(!format && 'break-all')}>
              <ScalarValue value={v} format={format} />
            </span>
          ))}
        </span>
      )
    }
    const columns = recordColumns(value)
    if (columns && depth < 2) {
      return <RecordTable rows={value as Record<string, unknown>[]} columns={columns} />
    }
    return <JsonBlock value={value} />
  }
  if (isPlainObject(value) && depth < 2) {
    const flat = Object.values(value).every(
      (v) => v === null || isScalar(v) || (Array.isArray(v) && v.every(isScalar))
    )
    if (flat || depth === 0) return <ObjectValue value={value} depth={depth} />
  }
  return <JsonBlock value={value} />
}

/** True when a value renders as a block (table, list, JSON) that needs the full row width. */
export function isWideValue(value: unknown): boolean {
  return (Array.isArray(value) && !value.every(isScalar)) || isPlainObject(value)
}
