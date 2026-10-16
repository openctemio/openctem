'use client'

import { useTranslation } from '@/context/i18n-provider'
import { useRef, useCallback, useState } from 'react'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { ChevronDown, Loader2, Check } from 'lucide-react'
import { FINDING_STATUS_CONFIG } from '../types'
import type { FindingStatus } from '../types'
import { useSWRConfig } from 'swr'
import { findingTransitionsKey, useFindingTransitions } from '../api/use-finding-transitions'
import { firstReason } from '../lib/transition-reasons'

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
  /** The finding whose moves the API lists (its transition engine). */
  findingId: string
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
}

/**
 * The status menu of a finding. Its moves come from the API, for this user:
 * an allowed move is offered, a blocked one is shown disabled with the
 * reason ("why can't I move this?"). Loaded when the menu opens. A
 * duplicate is never a plain status change: Mark duplicate picks the
 * canonical finding.
 */
export function StatusSelect({
  findingId,
  value,
  onChange,
  disabled = false,
  loading = false,
  size = 'sm',
  showCheck = false,
}: StatusSelectProps) {
  const { t } = useTranslation()
  const currentConfig = FINDING_STATUS_CONFIG[value]
  const [open, setOpen] = useState(false)
  const { data, isLoading } = useFindingTransitions(open ? findingId : null)
  const moves = (data?.transitions ?? []).filter((m) => m.mode !== 'duplicate_picker')
  const { mutate } = useSWRConfig()
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
      // The moves depend on the status: drop them, so the next open asks again.
      void mutate(findingTransitionsKey(findingId), undefined, { revalidate: false })
      // Reset after a short delay to allow for the API call to complete
      setTimeout(() => {
        isProcessingRef.current = false
      }, 500)
    },
    [onChange, loading, disabled, mutate, findingId]
  )

  return (
    <TooltipProvider delayDuration={300}>
      <DropdownMenu open={open} onOpenChange={setOpen}>
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
        <DropdownMenuContent align="start" className="w-64">
          {isLoading && (
            <DropdownMenuItem disabled className="flex items-center gap-2">
              <Loader2 className="h-3 w-3 animate-spin" />
              {t('findings.statusSelect.loading', 'Loading moves…')}
            </DropdownMenuItem>
          )}
          {!isLoading && moves.length === 0 && (
            <DropdownMenuItem disabled>
              {t('findings.statusSelect.none', 'No status change available')}
            </DropdownMenuItem>
          )}
          {moves.map((move) => {
            const status = move.to
            const config = FINDING_STATUS_CONFIG[status]
            if (!config) return null
            const reason = move.allowed ? undefined : firstReason(t, move.blocked)
            return (
              <Tooltip key={status}>
                <TooltipTrigger asChild>
                  <span className="block">
                    <DropdownMenuItem
                      onClick={() => move.allowed && handleChange(status)}
                      className="flex items-center gap-2"
                      disabled={!move.allowed || disabled || loading}
                      aria-describedby={reason ? `status-reason-${status}` : undefined}
                    >
                      <div
                        className={`h-2 w-2 rounded-full ${config.bgColor.replace('/20', '')}`}
                      />
                      {t(config.labelKey, config.label)}
                      {showCheck && status === value && <Check className="ms-auto h-3 w-3" />}
                    </DropdownMenuItem>
                  </span>
                </TooltipTrigger>
                <TooltipContent side="right" className="max-w-[240px]">
                  <p id={reason ? `status-reason-${status}` : undefined} className="text-xs">
                    {reason ?? describe(status)}
                  </p>
                </TooltipContent>
              </Tooltip>
            )
          })}
        </DropdownMenuContent>
      </DropdownMenu>
    </TooltipProvider>
  )
}
