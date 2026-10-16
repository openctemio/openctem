'use client'

/**
 * One suggestion: the fix, how many findings and assets it covers, the risk
 * it removes, who it would go to and why it was grouped. Nothing happens
 * until a person accepts it.
 */

import { forwardRef, useState } from 'react'
import { AlertTriangle, ChevronDown, ChevronUp, EyeOff, Sparkles } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { RemediationSuggestion } from '../api/types'
import { useOwnerNames } from '../api/use-owner-names'
import { fixSteps, riskPartsList } from '../lib/hub'
import { FixStepsBlock } from './fix-steps'

export interface SuggestionCardProps {
  suggestion: RemediationSuggestion
  active?: boolean
  selected?: boolean
  canWrite: boolean
  onSelect?: (selected: boolean) => void
  onAccept: () => void
  onEdit: () => void
  onDismiss: () => void
  onSnooze: () => void
  onFocus?: () => void
  explainOpen?: boolean
  onToggleExplain?: () => void
}

export const SuggestionCard = forwardRef<HTMLDivElement, SuggestionCardProps>(
  function SuggestionCard(
    {
      suggestion: s,
      active,
      selected,
      canWrite,
      onSelect,
      onAccept,
      onEdit,
      onDismiss,
      onSnooze,
      onFocus,
      explainOpen,
      onToggleExplain,
    },
    ref
  ) {
    const { t } = useTranslation()
    const owners = useOwnerNames()
    const [localOpen, setLocalOpen] = useState(false)
    const open = explainOpen ?? localOpen
    const toggle = onToggleExplain ?? (() => setLocalOpen((v) => !v))
    const parts = riskPartsList(s)
    const blocked = s.hidden_members > 0
    const steps = fixSteps(s.fix_spec, s.action_key)

    const ownerLabel = (p: RemediationSuggestion['partitions'][number]) => {
      if (p.owner_rule === 'default_queue') return t('remediationHub.owner.defaultQueue')
      const names = [owners.user(p.owner_user_id), owners.group(p.owner_group_id)].filter(Boolean)
      return names.length ? names.join(' · ') : t('remediationHub.owner.assetOwner')
    }

    return (
      <div
        ref={ref}
        role="article"
        tabIndex={-1}
        aria-label={s.title}
        aria-current={active ? 'true' : undefined}
        onFocus={onFocus}
        onClick={onFocus}
        className={cn(
          'bg-card rounded-lg border p-4 outline-none transition-shadow',
          active && 'ring-primary/60 ring-2',
          selected && 'border-primary/60'
        )}
        data-testid="suggestion-card"
      >
        <div className="flex flex-wrap items-start gap-3">
          {onSelect && canWrite && (
            <Checkbox
              className="mt-1"
              checked={selected}
              onCheckedChange={(v) => onSelect(v === true)}
              aria-label={t('remediationHub.suggestions.select', undefined, { title: s.title })}
              disabled={blocked}
            />
          )}
          <div className="min-w-0 flex-1 basis-64">
            <div className="text-muted-foreground flex flex-wrap items-center gap-2 text-xs">
              <Badge variant="outline">{t(`remediationHub.kind.${s.kind}`)}</Badge>
              <span>{t(`remediationHub.keyKind.${s.key_kind}`, s.key_kind)}</span>
              {s.has_urgent && (
                <Badge variant="destructive" className="gap-1">
                  <AlertTriangle className="size-3" aria-hidden />
                  {t('remediationHub.suggestions.urgent')}
                </Badge>
              )}
              {s.confidence < 1 && (
                <span title={t('remediationHub.suggestions.confidenceHint')}>
                  {t('remediationHub.suggestions.confidence', undefined, {
                    pct: Math.round(s.confidence * 100),
                  })}
                </span>
              )}
            </div>
            <h3 className="mt-1 text-base font-semibold break-words">{s.title}</h3>
            <p className="text-muted-foreground mt-1 text-sm">
              {t('remediationHub.suggestions.covers', undefined, {
                findings: s.member_count,
                assets: s.risk_parts?.assets ?? 0,
                risk: s.risk_points,
              })}
              {parts.length > 0 && (
                <span className="ms-2">
                  ({parts.map((p) => `${p.label} ${p.count}`).join(' · ')})
                </span>
              )}
            </p>
            {s.partitions.length > 0 && (
              <ul
                className="mt-2 flex flex-wrap gap-2 text-xs"
                aria-label={t('remediationHub.suggestions.owners')}
              >
                {s.partitions.map((p, i) => (
                  <li key={i} className="bg-muted rounded-md px-2 py-1">
                    {ownerLabel(p)} ·{' '}
                    {t('remediationHub.suggestions.findingsCount', undefined, {
                      n: p.finding_ids.length,
                    })}
                  </li>
                ))}
              </ul>
            )}
            {(blocked || s.truncated > 0) && (
              <ul className="mt-2 space-y-1 text-xs text-warning">
                {blocked && (
                  <li className="flex items-center gap-1">
                    <EyeOff className="size-3" aria-hidden />
                    {t('remediationHub.suggestions.hidden', undefined, { n: s.hidden_members })}
                  </li>
                )}
                {s.truncated > 0 && (
                  <li>
                    {t('remediationHub.suggestions.truncated', undefined, { n: s.truncated })}
                  </li>
                )}
              </ul>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {canWrite && (
              <>
                <Button size="sm" onClick={onAccept} disabled={blocked} aria-keyshortcuts="a">
                  {t('remediationHub.actions.accept')}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={onEdit}
                  disabled={blocked}
                  aria-keyshortcuts="e"
                >
                  {t('remediationHub.actions.edit')}
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={onDismiss}
                  disabled={blocked}
                  aria-keyshortcuts="d"
                >
                  {t('remediationHub.actions.dismiss')}
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={onSnooze}
                  disabled={blocked}
                  aria-keyshortcuts="s"
                >
                  {t('remediationHub.actions.snooze')}
                </Button>
              </>
            )}
            <Button
              size="sm"
              variant="ghost"
              onClick={toggle}
              aria-expanded={open}
              aria-keyshortcuts="?"
            >
              <Sparkles className="size-4" aria-hidden />
              {t('remediationHub.actions.why')}
              {open ? (
                <ChevronUp className="size-4" aria-hidden />
              ) : (
                <ChevronDown className="size-4" aria-hidden />
              )}
            </Button>
          </div>
        </div>
        {open && (
          <div
            className="bg-muted/40 mt-3 space-y-2 rounded-md p-3 text-sm"
            data-testid="suggestion-explain"
          >
            <p>{t(`remediationHub.explain.${s.key_kind}`, t('remediationHub.explain.other'))}</p>
            <p className="text-muted-foreground text-xs break-all">
              {t('remediationHub.explain.key', undefined, { key: s.action_key })}
            </p>
            <p className="text-muted-foreground text-xs">
              {t('remediationHub.explain.algorithm', undefined, {
                algorithm: s.algorithm,
                version: s.algorithm_version,
              })}
            </p>
            {s.kind !== 'new_group' && (
              <p className="text-muted-foreground text-xs">
                {t(`remediationHub.explain.kind.${s.kind}`)}
              </p>
            )}
            <FixStepsBlock steps={steps} />
          </div>
        )}
      </div>
    )
  }
)
