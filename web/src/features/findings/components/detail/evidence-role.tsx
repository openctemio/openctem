'use client'

/**
 * The reader's view of a finding's evidence item: what it shows (role) and
 * where it sits (order). One set of components serves every place that shows
 * or changes it, so a role looks and reads the same everywhere.
 *
 *   EvidenceRoleChip     the role as a pill (read only)
 *   EvidenceRoleSelect   change the role (people with findings:write)
 *   EvidenceOrderButtons move an item up or down in the order
 */

import * as React from 'react'
import { ArrowDown, ArrowUp, Paperclip, Scale, ShieldCheck, Target } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { EVIDENCE_ROLES, type EvidenceRole } from '../../lib/evidence-role'

const ROLE_ICON: Record<EvidenceRole, React.ComponentType<{ className?: string }>> = {
  baseline: Scale,
  proof: Target,
  verification: ShieldCheck,
  supporting: Paperclip,
}

const ROLE_FALLBACK: Record<EvidenceRole, string> = {
  baseline: 'Baseline',
  proof: 'Proof',
  verification: 'Verification',
  supporting: 'Supporting',
}

/** The translated name of a role. */
export function useEvidenceRoleLabel(): (role: EvidenceRole) => string {
  const { t } = useTranslation()
  return React.useCallback(
    (role: EvidenceRole) => t(`findings.evidenceRole.${role}`, ROLE_FALLBACK[role]),
    [t]
  )
}

export function EvidenceRoleChip({ role, className }: { role: EvidenceRole; className?: string }) {
  const { t } = useTranslation()
  const label = useEvidenceRoleLabel()
  const Icon = ROLE_ICON[role]
  return (
    <Badge
      variant="outline"
      className={cn(
        'gap-1 text-xs',
        role === 'proof' && 'border-primary/50 text-primary',
        role === 'supporting' && 'text-muted-foreground',
        className
      )}
      title={t(`findings.evidenceRole.${role}Hint`, '')}
      data-testid="evidence-role-chip"
      data-role={role}
    >
      <Icon className="h-3 w-3" aria-hidden />
      {label(role)}
    </Badge>
  )
}

export function EvidenceRoleSelect({
  value,
  onChange,
  disabled,
}: {
  value: EvidenceRole
  onChange: (role: EvidenceRole) => void
  disabled?: boolean
}) {
  const { t } = useTranslation()
  const label = useEvidenceRoleLabel()
  return (
    <Select value={value} onValueChange={(v) => onChange(v as EvidenceRole)} disabled={disabled}>
      <SelectTrigger
        size="sm"
        className="h-7 w-auto gap-1 px-2 text-xs"
        aria-label={t('findings.evidenceRole.change', 'Change what this evidence shows')}
      >
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {EVIDENCE_ROLES.map((r) => (
          <SelectItem key={r} value={r}>
            {label(r)}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

export function EvidenceOrderButtons({
  index,
  count,
  onMove,
  disabled,
}: {
  index: number
  count: number
  onMove: (direction: 'up' | 'down') => void
  disabled?: boolean
}) {
  const { t } = useTranslation()
  return (
    <div className="flex items-center" role="group">
      <Button
        type="button"
        variant="ghost"
        size="sm"
        className="h-7 w-7 p-0"
        disabled={disabled || index <= 0}
        onClick={() => onMove('up')}
        aria-label={t('findings.evidenceRole.moveUp', 'Move this evidence up')}
      >
        <ArrowUp className="h-3.5 w-3.5" aria-hidden />
      </Button>
      <Button
        type="button"
        variant="ghost"
        size="sm"
        className="h-7 w-7 p-0"
        disabled={disabled || index >= count - 1}
        onClick={() => onMove('down')}
        aria-label={t('findings.evidenceRole.moveDown', 'Move this evidence down')}
      >
        <ArrowDown className="h-3.5 w-3.5" aria-hidden />
      </Button>
    </div>
  )
}
