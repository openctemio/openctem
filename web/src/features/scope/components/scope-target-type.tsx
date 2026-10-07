'use client'

/**
 * Scope entry kinds (research/53 §4.1, SC4): six kinds, detected from the
 * pattern. Nobody picks "domain" or "subdomain": `x` and `*.x` are both
 * domains (the coverage choice says how far they reach). A picker appears
 * only to override a detection, with these six kinds.
 *
 * Until the API detects kinds itself, the web sends the detected kind as
 * `target_type` / `exclusion_type`; rows stored under older type names are
 * labelled through `scopeTargetTypeLabel` (`subdomain` reads as Domain).
 */

import { Cloud, GitBranch, Globe, Link, Server } from 'lucide-react'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

export type ScopeKind =
  'domain' | 'ip_address' | 'ip_range' | 'url' | 'repository' | 'cloud_account'

export const SCOPE_KINDS: ScopeKind[] = [
  'domain',
  'ip_address',
  'ip_range',
  'url',
  'repository',
  'cloud_account',
]

/** Exclusions have no cloud-account kind. */
export const EXCLUSION_KINDS: ScopeKind[] = [
  'domain',
  'ip_address',
  'ip_range',
  'url',
  'repository',
]

const iconClass = 'h-4 w-4'

export const SCOPE_KIND_LABEL: Record<ScopeKind, string> = {
  domain: 'Domain',
  ip_address: 'IP address',
  ip_range: 'IP range',
  url: 'URL',
  repository: 'Repository',
  cloud_account: 'Cloud account',
}

export const SCOPE_KIND_PLACEHOLDER: Record<ScopeKind, string> = {
  domain: 'example.com',
  ip_address: '203.0.113.7',
  ip_range: '203.0.113.0/24 or 203.0.113.10-203.0.113.20',
  url: 'https://app.example.com/portal',
  repository: 'github.com/acme/web',
  cloud_account: 'AWS:123456789012',
}

/** Older stored type names, read as one of the six kinds. */
const LEGACY_KIND: Record<string, ScopeKind> = {
  subdomain: 'domain',
  email_domain: 'domain',
  certificate: 'domain',
  cidr: 'ip_range',
  api: 'url',
  website: 'url',
  project: 'repository',
}

export function scopeKindOf(type: string | undefined): ScopeKind | undefined {
  if (!type) return undefined
  if ((SCOPE_KINDS as string[]).includes(type)) return type as ScopeKind
  return LEGACY_KIND[type]
}

export const SCOPE_TARGET_TYPE_ICON: Record<string, React.ReactNode> = {
  domain: <Globe className={iconClass} />,
  ip_address: <Server className={iconClass} />,
  ip_range: <Server className={iconClass} />,
  url: <Link className={iconClass} />,
  repository: <GitBranch className={iconClass} />,
  cloud_account: <Cloud className={iconClass} />,
}

/** Label of a stored type: one of the six kinds, else the words of the type. */
export function scopeTargetTypeLabel(type: string): string {
  const kind = scopeKindOf(type)
  if (kind) return SCOPE_KIND_LABEL[kind]
  const s = type.replace(/_/g, ' ')
  return s.charAt(0).toUpperCase() + s.slice(1)
}

export function scopeKindIcon(type: string | undefined): React.ReactNode {
  const kind = scopeKindOf(type)
  return kind ? SCOPE_TARGET_TYPE_ICON[kind] : null
}

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/
const IPV6 = /^[0-9a-f:]+$/i

function isIP(v: string): boolean {
  return IPV4.test(v) || (v.includes(':') && IPV6.test(v) && v.split(':').length >= 3)
}

/**
 * The kind a pattern stands for, or undefined when the detector cannot tell
 * (the dialog then asks). Wildcards (`*.x`) are domains.
 */
export function detectScopeKind(raw: string): ScopeKind | undefined {
  const v = raw.trim()
  if (!v || /\s/.test(v)) return undefined
  if (/^(aws|gcp|azure):[A-Za-z0-9_-]+$/i.test(v)) return 'cloud_account'
  if (/^(https?:\/\/|\*:\/\/)/i.test(v)) return 'url'
  if (isIP(v)) return 'ip_address'
  const slash = v.indexOf('/')
  if (slash > 0 && isIP(v.slice(0, slash)) && /^\d{1,3}$/.test(v.slice(slash + 1)))
    return 'ip_range'
  const dash = v.indexOf('-')
  if (dash > 0 && isIP(v.slice(0, dash)) && isIP(v.slice(dash + 1))) return 'ip_range'
  if (slash > 0 && /^[a-z0-9.-]+\.[a-z]{2,}(\/[A-Za-z0-9._*-]+)+$/i.test(v)) return 'repository'
  if (/^(\*{1,2}\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$/i.test(v))
    return 'domain'
  return undefined
}

/** The stored type names a kind filter matches (older rows included). */
export function storedTypesFor(
  kind: ScopeKind,
  list: 'entries' | 'exclusions' = 'entries'
): string {
  const legacy = Object.entries(LEGACY_KIND)
    .filter(([t, k]) => k === kind && (list === 'entries' || EXCLUSION_LEGACY.has(t)))
    .map(([t]) => t)
  return [kind, ...legacy].join(',')
}

/** Older type names that exclusions also used (the API refuses the rest there). */
const EXCLUSION_LEGACY = new Set(['subdomain', 'cidr'])

/** Kinds a member may request (one name or one address, RFC-054 §6.1). */
export const REQUESTABLE_TARGET_TYPES: ScopeKind[] = ['domain', 'ip_address']

interface ScopeKindSelectProps {
  value: string
  onValueChange: (v: string) => void
  disabled?: boolean
  /** Only these kinds (default: all six). */
  only?: ScopeKind[]
  /** Adds an "All kinds" item with value "all" (filters). */
  withAll?: boolean
  className?: string
  'aria-label'?: string
  id?: string
}

export function ScopeTargetTypeSelect({
  value,
  onValueChange,
  disabled,
  only,
  withAll,
  className,
  id,
  'aria-label': ariaLabel,
}: ScopeKindSelectProps) {
  const kinds = only ?? SCOPE_KINDS
  return (
    <Select value={scopeKindOf(value) ?? value} onValueChange={onValueChange} disabled={disabled}>
      <SelectTrigger className={className} aria-label={ariaLabel} id={id}>
        <SelectValue placeholder="Kind" />
      </SelectTrigger>
      <SelectContent>
        {withAll && <SelectItem value="all">All kinds</SelectItem>}
        {kinds.map((k) => (
          <SelectItem key={k} value={k}>
            <div className="flex items-center gap-2">
              {SCOPE_TARGET_TYPE_ICON[k]}
              {SCOPE_KIND_LABEL[k]}
            </div>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}
