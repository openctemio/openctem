'use client'

/**
 * One type attribute in an inventory row (research/77). The renderer is
 * chosen by the attribute's kind and its property format, never by the asset
 * type, so a new type needs no cell code:
 *
 *  - bool: Yes / No;
 *  - enum: a badge;
 *  - time: a relative date; an expiry (`expires_at`, `not_after`) is red once
 *    past and amber within 30 days;
 *  - list: the first value and "+N" (IPs in mono);
 *  - int / number: tabular figures;
 *  - string: text, a safe external link for `url`, mono for `code` and `ip`;
 *  - object: not shown in a row (the drawer lists it).
 *
 * A value the asset does not carry is the muted dash, never a default.
 */
import { Badge } from '@/components/ui/badge'
import { SafeExternalLink } from '@/components/safe-external-link'
import { RelativeTime } from '@/features/shared'
import { ASSET_PROPERTIES } from '@/features/asset-types/registry.generated'
import type { TypeAttribute } from '@/features/asset-types/lib/type-view'
import { cn } from '@/lib/utils'
import type { Asset } from '../../types'
import { attributeStrings, attributeValue } from '../../lib/attribute-value'
import { OverflowChips } from '../service-cells/overflow-chips'
import { propertyLabel } from '@/features/asset-types/lib/property-schema'

/** Attributes that are an expiry date: shown with how close it is. */
const EXPIRY_KEYS: ReadonlySet<string> = new Set(['expires_at', 'not_after'])

/** Days before an expiry turns amber (the certificate-health window). */
const EXPIRY_WARN_DAYS = 30

const Dash = () => <span className="text-muted-foreground">—</span>

function ExpiryCell({ value }: { value: string }) {
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return <Dash />
  const days = Math.ceil((d.getTime() - Date.now()) / 86_400_000)
  return (
    <RelativeTime
      date={d}
      className={cn(
        'whitespace-nowrap',
        days < 0 && 'font-medium text-destructive',
        days >= 0 && days <= EXPIRY_WARN_DAYS && 'font-medium text-warning'
      )}
    />
  )
}

export function AttributeCell({ asset, attribute }: { asset: Asset; attribute: TypeAttribute }) {
  const { key, kind } = attribute
  const format = ASSET_PROPERTIES[key]?.format

  if (kind === 'list') {
    const values = attributeStrings(asset, key)
    if (values.length === 0) return <Dash />
    return (
      <div className="flex max-w-[240px] flex-wrap items-center gap-1">
        <OverflowChips
          label={propertyLabel(key)}
          values={values}
          mono={format === 'ip' || format === 'code'}
          showLabel={false}
        />
      </div>
    )
  }

  const v = attributeValue(asset, key)
  if (v === undefined || kind === 'object') return <Dash />

  if (kind === 'bool' || typeof v === 'boolean') {
    if (typeof v !== 'boolean') return <Dash />
    return v ? (
      <Badge variant="outline" className="font-normal">
        Yes
      </Badge>
    ) : (
      <span className="text-sm text-muted-foreground">No</span>
    )
  }

  const text = String(v)
  if (kind === 'time') {
    return EXPIRY_KEYS.has(key) ? (
      <ExpiryCell value={text} />
    ) : (
      <RelativeTime date={text} className="whitespace-nowrap" />
    )
  }
  if (kind === 'enum') {
    return (
      <Badge variant="outline" className="font-normal">
        {text}
      </Badge>
    )
  }
  if (kind === 'int' || kind === 'number') {
    return <span className="text-sm tabular-nums">{text}</span>
  }
  if (format === 'url') {
    return (
      <SafeExternalLink
        href={text}
        className="block max-w-[220px] truncate text-sm text-primary hover:underline"
        title={text}
      >
        {text}
      </SafeExternalLink>
    )
  }
  return (
    <span
      className={cn(
        'block max-w-[220px] truncate text-sm',
        (format === 'code' || format === 'ip') && 'font-mono text-xs'
      )}
      title={text}
    >
      {text}
    </span>
  )
}
