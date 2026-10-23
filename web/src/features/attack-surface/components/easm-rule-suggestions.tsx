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
import { ErrorState, TonePill, type PillTone } from '@/features/shared'
import { useUrlFilter } from '@/hooks/use-url-param'
import { coversText, scopeRefusalLabel } from '@/features/scope'
import { Permission, usePermissions } from '@/lib/permissions'
import { useEASMRuleSuggestions, type EASMRuleSuggestion } from '../hooks/use-easm-rules'
import { EASMRuleDialog } from './easm-rule-dialog'

type T = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

function strengthOf(
  t: T,
  strength: string | undefined
): { tone: PillTone; label: string; hint: string } {
  switch (strength) {
    case 'strong':
      return {
        tone: 'success',
        label: t('easmReview.suggestions.strong', 'Strong'),
        hint: t('easmReview.suggestions.strongHint', 'Under a domain you verified.'),
      }
    case 'medium':
      return {
        tone: 'info',
        label: t('easmReview.suggestions.medium', 'Medium'),
        hint: t(
          'easmReview.suggestions.mediumHint',
          'Found from one of your roots, seeds or a known network.'
        ),
      }
    default:
      return {
        tone: 'muted',
        label: t('easmReview.suggestions.weak', 'Weak'),
        hint: t('easmReview.suggestions.weakHint', 'Only the names themselves point to it.'),
      }
  }
}

/** One evidence hint in words. */
export function hintText(t: T, h: { kind?: string; value?: string }): string {
  const v = h.value ?? ''
  switch (h.kind) {
    case 'verified_domain':
      return t('easmReview.hint.verifiedDomain', 'Under {value}, a domain you verified', {
        value: v,
      })
    case 'seed':
      return t('easmReview.hint.seed', 'Under your seed {value}', { value: v })
    case 'asn':
      return t('easmReview.hint.asn', 'Network {value}', { value: v })
    case 'cert_org':
      return t('easmReview.hint.certOrg', 'Certificates issued to {value}', { value: v })
    case 'same_ns_as_verified':
      return t('easmReview.hint.sameNs', 'Same name server as a verified domain ({value})', {
        value: v,
      })
    case 'rdap_allocation':
      return t('easmReview.hint.rdap', 'Address block {value}', { value: v })
    default:
      if (h.kind?.startsWith('discovering_'))
        return t('easmReview.hint.discovering', 'Found from {value}', { value: v })
      return `${(h.kind ?? '').replace(/_/g, ' ')} ${v}`.trim()
  }
}

/** An address or a service on one ("203.0.113.5", "203.0.113.5:443", "[2001:db8::1]:443"). */
function isAddressName(name: string | undefined): boolean {
  const n = (name ?? '').trim()
  return /^\d{1,3}(\.\d{1,3}){3}(:\d+.*)?$/.test(n) || /^\[?[0-9a-f:]+\]?(:\d+.*)?$/i.test(n)
}

function sampleNames(items: { name?: string }[]): string {
  return (
    items
      .slice(0, 3)
      .map((i) => i.name)
      .join(', ') + (items.length > 3 ? '…' : '')
  )
}

export function EASMRuleSuggestions({
  onApplied,
  namesOnly = false,
}: {
  onApplied: () => void
  /** Leave out address rules and addresses: the addresses card holds them. */
  namesOnly?: boolean
}) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const { suggestions, isLoading, error, mutate } = useEASMRuleSuggestions()
  const [, setAll] = useUrlFilter('all', '0')
  const [open, setOpen] = useState<{
    s: EASMRuleSuggestion
    action: 'accept_rule' | 'reject_rule'
  } | null>(null)
  // A rule creates a scope entry or exclusion: scope:write and assets:write.
  const canDecide = can(Permission.ScopeWrite) && can(Permission.AssetsWrite)

  if (error) {
    return (
      <ErrorState
        title={t('easmReview.suggestions.errorTitle', 'suggested rules')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading && !suggestions) {
    return (
      <div className="grid gap-3 md:grid-cols-2">
        <Skeleton className="h-36 rounded-lg" />
        <Skeleton className="h-36 rounded-lg" />
      </div>
    )
  }
  const list = (suggestions?.suggestions ?? []).filter((s) => !namesOnly || s.kind !== 'ip_cidr')
  const individual = (suggestions?.individual ?? []).filter(
    (i) => !namesOnly || !isAddressName(i.name)
  )
  if (list.length === 0 && individual.length === 0) return null

  return (
    <section aria-labelledby="rule-suggestions" className="space-y-3">
      <div>
        <h2 id="rule-suggestions" className="text-base font-semibold">
          {t('easmReview.suggestions.title', 'Suggested rules')}
        </h2>
        <p className="text-sm text-muted-foreground">
          {t(
            'easmReview.suggestions.intro',
            'Decide a group of names at once. Accepting adds a scope entry (it goes through approval like any other); rejecting adds an exclusion and marks the names not yours.'
          )}
        </p>
      </div>
      <ul className="grid gap-3 md:grid-cols-2">
        {list.map((s) => {
          const strength = strengthOf(t, s.strength)
          return (
            <li key={s.id ?? s.pattern} className="flex flex-col gap-2 rounded-lg border p-3">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <code className="break-all text-sm font-medium">{s.pattern}</code>
                  <p className="text-xs text-muted-foreground">
                    {s.target_type === 'domain'
                      ? t('easmReview.suggestions.covers', 'Covers {what}', {
                          what: coversText({ pattern: s.pattern }),
                        })
                      : t('easmReview.suggestions.everyAddress', 'Every address in {pattern}', {
                          pattern: s.pattern ?? '',
                        })}
                  </p>
                </div>
                <TonePill tone={strength.tone} label={strength.label} title={strength.hint} />
              </div>
              <p className="text-sm">
                <span className="font-medium tabular-nums">{s.covered ?? 0}</span>{' '}
                {s.covered === 1
                  ? t('easmReview.suggestions.pendingOne', 'pending name')
                  : t('easmReview.suggestions.pendingMany', 'pending names')}
                {(s.covered_sample ?? []).length > 0 && (
                  <span className="text-muted-foreground">
                    : {(s.covered_sample ?? []).slice(0, 3).join(', ')}
                    {(s.covered ?? 0) > 3 ? '…' : ''}
                  </span>
                )}
              </p>
              {(s.blocked ?? 0) > 0 && (
                <p className="text-xs text-muted-foreground">
                  {t('easmReview.suggestions.stayOut', '{n} stay out:', { n: s.blocked ?? 0 })}{' '}
                  {(s.blocked_sample ?? [])
                    .slice(0, 2)
                    .map((b) => `${b.name} (${scopeRefusalLabel(t, b.code)})`)
                    .join(', ')}
                </p>
              )}
              {(s.hints ?? []).length > 0 && (
                <ul
                  className="space-y-0.5 text-xs text-muted-foreground"
                  aria-label={t('easmReview.suggestions.evidence', 'Evidence')}
                >
                  {(s.hints ?? []).slice(0, 3).map((h, i) => (
                    <li key={i} className="flex gap-1">
                      <Info className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
                      {hintText(t, h)}
                    </li>
                  ))}
                </ul>
              )}
              {canDecide && (
                <div className="mt-auto flex flex-wrap gap-2 pt-1">
                  <Button size="sm" onClick={() => setOpen({ s, action: 'accept_rule' })}>
                    <Check className="h-4 w-4" aria-hidden />
                    {t('easmReview.rule.accept', 'Accept as rule')}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setOpen({ s, action: 'reject_rule' })}
                  >
                    <X className="h-4 w-4" aria-hidden />
                    {t('easmReview.rule.reject', 'Reject as rule')}
                  </Button>
                </div>
              )}
            </li>
          )
        })}
      </ul>
      {individual.length > 0 && (
        <p className="text-sm text-muted-foreground">
          {namesOnly
            ? t(
                individual.length === 1
                  ? 'easmReview.suggestions.namesOne'
                  : 'easmReview.suggestions.namesMany',
                individual.length === 1
                  ? '{n} name fits no rule; decide it one by one ({names}).'
                  : '{n} names fit no rule; decide them one by one ({names}).',
                { n: individual.length, names: sampleNames(individual) }
              )
            : t(
                individual.length === 1
                  ? 'easmReview.suggestions.individualOne'
                  : 'easmReview.suggestions.individualMany',
                individual.length === 1
                  ? '{n} shared or CDN address is never grouped; decide it one by one in the list below ({names}).'
                  : '{n} shared or CDN addresses are never grouped; decide them one by one in the list below ({names}).',
                { n: individual.length, names: sampleNames(individual) }
              )}
          {namesOnly && (
            <>
              {' '}
              <button
                type="button"
                className="text-primary underline-offset-2 hover:underline"
                onClick={() => setAll('1')}
              >
                {t('attackSurface.suggestions.showAll', 'Show all items')}
              </button>
            </>
          )}
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
