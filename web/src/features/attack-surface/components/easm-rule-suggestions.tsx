'use client'

/**
 * Review by rule (RFC-054 §6.7): pending names grouped into suggested rules
 * (a wildcard per label level up to the registrable domain, an IP /24 or
 * /48), each with how many pending names it covers, which stay out and why,
 * and the evidence we already hold. Accept as rule / Reject as rule open a
 * preview of exactly what changes (EASMRuleDialog). Shared or CDN addresses
 * are never grouped: they are listed to decide one by one.
 */

import { useState } from 'react'
import { Check, Info, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { TonePill, type PillTone } from '@/features/shared'
import { coversText, scopeRefusalLabel } from '@/features/scope'
import { Permission, usePermissions } from '@/lib/permissions'
import { useEASMRuleSuggestions, type EASMRuleSuggestion } from '../hooks/use-easm-rules'
import { EASMRuleDialog } from './easm-rule-dialog'

const STRENGTH: Record<string, { tone: PillTone; label: string; hint: string }> = {
  strong: { tone: 'success', label: 'Strong', hint: 'Under a domain you verified.' },
  medium: {
    tone: 'info',
    label: 'Medium',
    hint: 'Found from one of your roots, seeds or a known network.',
  },
  weak: { tone: 'muted', label: 'Weak', hint: 'Only the names themselves point to it.' },
}

/** One evidence hint in words. */
export function hintText(h: { kind?: string; value?: string }): string {
  const v = h.value ?? ''
  switch (h.kind) {
    case 'verified_domain':
      return `Under ${v}, a domain you verified`
    case 'seed':
      return `Under your seed ${v}`
    case 'asn':
      return `Network ${v}`
    case 'cert_org':
      return `Certificates issued to ${v}`
    case 'same_ns_as_verified':
      return `Same name server as a verified domain (${v})`
    case 'rdap_allocation':
      return `Address block ${v}`
    default:
      if (h.kind?.startsWith('discovering_')) return `Found from ${v}`
      return `${(h.kind ?? '').replace(/_/g, ' ')} ${v}`.trim()
  }
}

export function EASMRuleSuggestions({ onApplied }: { onApplied: () => void }) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const { suggestions, isLoading, error, mutate } = useEASMRuleSuggestions()
  const [open, setOpen] = useState<{
    s: EASMRuleSuggestion
    action: 'accept_rule' | 'reject_rule'
  } | null>(null)
  // A rule creates a scope entry or exclusion: scope:write and assets:write.
  const canDecide = can(Permission.ScopeWrite) && can(Permission.AssetsWrite)

  if (error) return null
  if (isLoading && !suggestions) {
    return (
      <div className="grid gap-3 md:grid-cols-2">
        <Skeleton className="h-36 rounded-lg" />
        <Skeleton className="h-36 rounded-lg" />
      </div>
    )
  }
  const list = suggestions?.suggestions ?? []
  const individual = suggestions?.individual ?? []
  if (list.length === 0 && individual.length === 0) return null

  return (
    <section aria-labelledby="rule-suggestions" className="space-y-3">
      <div>
        <h2 id="rule-suggestions" className="text-base font-semibold">
          Suggested rules
        </h2>
        <p className="text-sm text-muted-foreground">
          Decide a group of names at once. Accepting adds a scope entry (it goes through approval
          like any other); rejecting adds an exclusion and marks the names not yours.
        </p>
      </div>
      <ul className="grid gap-3 md:grid-cols-2">
        {list.map((s) => {
          const strength = STRENGTH[s.strength ?? 'weak'] ?? STRENGTH.weak
          return (
            <li key={s.id ?? s.pattern} className="flex flex-col gap-2 rounded-lg border p-3">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <code className="break-all text-sm font-medium">{s.pattern}</code>
                  <p className="text-xs text-muted-foreground">
                    {s.target_type === 'domain'
                      ? `Covers ${coversText({ pattern: s.pattern })}`
                      : `Every address in ${s.pattern}`}
                  </p>
                </div>
                <TonePill tone={strength.tone} label={strength.label} title={strength.hint} />
              </div>
              <p className="text-sm">
                <span className="font-medium tabular-nums">{s.covered ?? 0}</span> pending{' '}
                {s.covered === 1 ? 'name' : 'names'}
                {(s.covered_sample ?? []).length > 0 && (
                  <span className="text-muted-foreground">
                    : {(s.covered_sample ?? []).slice(0, 3).join(', ')}
                    {(s.covered ?? 0) > 3 ? '…' : ''}
                  </span>
                )}
              </p>
              {(s.blocked ?? 0) > 0 && (
                <p className="text-xs text-muted-foreground">
                  {s.blocked} stay out:{' '}
                  {(s.blocked_sample ?? [])
                    .slice(0, 2)
                    .map((b) => `${b.name} (${scopeRefusalLabel(t, b.code)})`)
                    .join(', ')}
                </p>
              )}
              {(s.hints ?? []).length > 0 && (
                <ul className="space-y-0.5 text-xs text-muted-foreground" aria-label="Evidence">
                  {(s.hints ?? []).slice(0, 3).map((h, i) => (
                    <li key={i} className="flex gap-1">
                      <Info className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
                      {hintText(h)}
                    </li>
                  ))}
                </ul>
              )}
              {canDecide && (
                <div className="mt-auto flex flex-wrap gap-2 pt-1">
                  <Button size="sm" onClick={() => setOpen({ s, action: 'accept_rule' })}>
                    <Check className="h-4 w-4" aria-hidden />
                    Accept as rule
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setOpen({ s, action: 'reject_rule' })}
                  >
                    <X className="h-4 w-4" aria-hidden />
                    Reject as rule
                  </Button>
                </div>
              )}
            </li>
          )
        })}
      </ul>
      {individual.length > 0 && (
        <p className="text-sm text-muted-foreground">
          {individual.length} shared or CDN{' '}
          {individual.length === 1 ? 'address is' : 'addresses are'} never grouped; decide{' '}
          {individual.length === 1 ? 'it' : 'them'} one by one in the list below (
          {individual
            .slice(0, 3)
            .map((i) => i.name)
            .join(', ')}
          {individual.length > 3 ? '…' : ''}).
        </p>
      )}
      <EASMRuleDialog
        suggestion={open?.s ?? null}
        action={open?.action ?? 'accept_rule'}
        onOpenChange={(o) => !o && setOpen(null)}
        onApplied={() => {
          void mutate()
          onApplied()
        }}
      />
    </section>
  )
}
