'use client'

import { useTranslation } from '@/context/i18n-provider'
import { useRef, useCallback } from 'react'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { ChevronDown, Loader2, Check } from 'lucide-react'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { FINDING_STATUS_CONFIG, STATUS_TRANSITIONS, getStatusesForSource } from '../types'
import type { FindingStatus } from '../types'

// Status transition descriptions for tooltips
const STATUS_DESCRIPTIONS: Partial<Record<FindingStatus, string>> = {
  new: 'Newly discovered finding awaiting triage',
  confirmed: 'Verified as a real security issue',
  in_progress: 'Remediation work has begun',
  fix_applied: 'Dev marked as fixed — awaiting a retest or security review',
  resolved: 'Issue has been fixed and verified',
  accepted: 'Risk acknowledged and accepted by stakeholders',
  false_positive: 'Determined to be a non-issue',
  duplicate: 'Already reported in another finding',
  draft: 'Pentest finding being drafted',
  in_review: 'Under peer review',
}

interface StatusSelectProps {
  /** Current status value */
  value: FindingStatus
  /** Called when status changes */
  onChange: (status: FindingStatus) => void
  /** Whether the select is disabled or loading */
  disabled?: boolean
  /** Show loading spinner */
  loading?: boolean
  /** Button size */
  size?: 'sm' | 'default'
  /** Show check mark for current selection */
  showCheck?: boolean
  /** Finding source — filters available statuses per source type */
  source?: string
}

export function StatusSelect({
  value,
  onChange,
  disabled = false,
  loading = false,
  size = 'sm',
  showCheck = false,
  source,
}: StatusSelectProps) {
  const { t } = useTranslation()
  const currentConfig = FINDING_STATUS_CONFIG[value]
  const allTransitions = STATUS_TRANSITIONS[value]
  // Filter transitions by source type (pentest vs automated have different valid statuses)
  const validStatuses = source ? getStatusesForSource(source) : undefined
  // Moving a finding to resolved needs findings:verify (the API refuses it
  // otherwise); without it the person marks fix_applied and a retest, a
  // covered scan or a security reviewer closes the finding.
  const { hasPermission } = usePermissions()
  const canResolve = hasPermission(Permission.FindingsVerify)
  // A duplicate must name the finding it duplicates, so it is never a plain
  // status change (the API refuses it): Mark duplicate picks the canonical
  // finding.
  const availableTransitions = (
    validStatuses ? allTransitions.filter((s) => validStatuses.includes(s)) : allTransitions
  ).filter((s) => (canResolve || s !== 'resolved') && s !== 'duplicate')
  const isProcessingRef = useRef(false)
  const describe = (s: FindingStatus) => {
    const en = STATUS_DESCRIPTIONS[s]
    return en ? t(`findings.statusSelect.desc.${s}`, en) : undefined
  }

  // Debounced onChange to prevent race conditions
  const handleChange = useCallback(
    (status: FindingStatus) => {
      if (isProcessingRef.current || loading || disabled) return
      isProcessingRef.current = true
      onChange(status)
      // Reset after a short delay to allow for the API call to complete
      setTimeout(() => {
        isProcessingRef.current = false
      }, 500)
    },
    [onChange, loading, disabled]
  )

  return (
    <TooltipProvider delayDuration={300}>
      <DropdownMenu>
        <Tooltip>
          <TooltipTrigger asChild>
            <DropdownMenuTrigger asChild>
              <Button
                variant="outline"
                size={size}
                className={`${size === 'sm' ? 'h-7 px-2 text-xs' : 'h-9 sm:h-8'} min-h-[32px] ${currentConfig.bgColor} ${currentConfig.textColor} border-0 hover:opacity-80`}
                disabled={disabled || loading}
              >
                {loading && <Loader2 className="me-1 h-3 w-3 animate-spin" />}
                {t(currentConfig.labelKey, currentConfig.label)}
                {!disabled && <ChevronDown className="ms-1 h-3 w-3" />}
              </Button>
            </DropdownMenuTrigger>
          </TooltipTrigger>
          <TooltipContent side="bottom" className="max-w-[200px]">
            <p className="text-xs">{describe(value)}</p>
          </TooltipContent>
        </Tooltip>
        <DropdownMenuContent align="start" className="w-56">
          {availableTransitions.map((status) => {
            const config = FINDING_STATUS_CONFIG[status]
            return (
              <Tooltip key={status}>
                <TooltipTrigger asChild>
                  <DropdownMenuItem
                    onClick={() => handleChange(status)}
                    className="flex items-center gap-2"
                    disabled={disabled || loading}
                  >
                    <div className={`h-2 w-2 rounded-full ${config.bgColor.replace('/20', '')}`} />
                    {t(config.labelKey, config.label)}
                    {showCheck && status === value && <Check className="ms-auto h-3 w-3" />}
                  </DropdownMenuItem>
                </TooltipTrigger>
                <TooltipContent side="right" className="max-w-[200px]">
                  <p className="text-xs">{describe(status)}</p>
                </TooltipContent>
              </Tooltip>
            )
          })}
        </DropdownMenuContent>
      </DropdownMenu>
    </TooltipProvider>
  )
}
