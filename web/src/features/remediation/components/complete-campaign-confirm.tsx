'use client'

/**
 * Asks before a remediation campaign (a "task") is completed while some of
 * its findings are still open, and says how many. Completing with nothing
 * open goes straight through. See `lib/campaign-completion.ts`.
 */

import * as React from 'react'

import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  completionWarning,
  completionWarningText,
  fetchLiveCampaignCounts,
  type CampaignCounts,
  type CompletionWarning,
} from '@/features/remediation/lib/campaign-completion'

interface Pending {
  warning: CompletionWarning
  selected: number
  proceed: () => void | Promise<void>
}

export interface ConfirmCampaignCompletion {
  /**
   * Completes the campaigns through `proceed`, after a confirmation when any
   * of them still has open findings. `fallback` holds the counts the page
   * already has, used for a campaign whose live counts cannot be read.
   */
  confirmCompletion: (
    ids: string[],
    proceed: () => void | Promise<void>,
    fallback?: Record<string, CampaignCounts | undefined>
  ) => Promise<void>
  /** Render once on the page. */
  completionDialog: React.ReactNode
}

export function useConfirmCampaignCompletion(): ConfirmCampaignCompletion {
  const [pending, setPending] = React.useState<Pending | null>(null)
  const [busy, setBusy] = React.useState(false)

  const confirmCompletion = React.useCallback<ConfirmCampaignCompletion['confirmCompletion']>(
    async (ids, proceed, fallback) => {
      const counts = await fetchLiveCampaignCounts(ids, fallback)
      const warning = completionWarning(counts)
      if (!warning) {
        await proceed()
        return
      }
      setPending({ warning, selected: ids.length, proceed })
    },
    []
  )

  const completionDialog = (
    <CompleteCampaignConfirmDialog
      warning={pending?.warning ?? null}
      selected={pending?.selected ?? 1}
      isLoading={busy}
      onCancel={() => setPending(null)}
      onConfirm={async () => {
        if (!pending) return
        setBusy(true)
        try {
          await pending.proceed()
        } finally {
          setBusy(false)
          setPending(null)
        }
      }}
    />
  )

  return { confirmCompletion, completionDialog }
}

export interface CompleteCampaignConfirmDialogProps {
  /** Null keeps the dialog closed. */
  warning: CompletionWarning | null
  /** How many campaigns are being completed (1 for a single task). */
  selected?: number
  isLoading?: boolean
  onConfirm: () => void
  onCancel: () => void
}

export function CompleteCampaignConfirmDialog({
  warning,
  selected = 1,
  isLoading,
  onConfirm,
  onCancel,
}: CompleteCampaignConfirmDialogProps) {
  const many = selected > 1
  return (
    <ConfirmDialog
      open={warning !== null}
      onOpenChange={(open) => !open && onCancel()}
      title={many ? 'Complete tasks with open findings?' : 'Complete with open findings?'}
      desc={
        warning ? (
          <div className="space-y-2">
            <p className="font-medium text-foreground">
              {completionWarningText(warning, selected)}
            </p>
            <p>
              {many ? 'The tasks are' : 'The task is'} marked completed with progress as it stands
              now. The open findings stay open; resolve them from the findings list or with
              &quot;Resolve open findings&quot;.
            </p>
          </div>
        ) : (
          ''
        )
      }
      confirmText="Complete anyway"
      isLoading={isLoading}
      handleConfirm={onConfirm}
    />
  )
}
