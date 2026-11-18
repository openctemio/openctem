'use client'

import { useCallback, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { useDisplayUser } from '@/hooks/use-display-user'
import { refreshPendingApprovalCount } from '@/hooks/use-dynamic-badges'
import { useApprovalDecision } from '@/features/findings/components/approval-decision'
import { QueueDecisionActions } from '@/features/shared/components/queue'
import { toDisplayText } from '@/lib/untrusted-text'
import { isOwnApproval } from '@/features/findings/lib/approvals'
import type { ApiApproval } from '@/features/findings/types'
import { ApprovalRow } from './approval-row'
import { QueueFrame } from './queue-frame'

/**
 * Awaiting my review: the pending requests the caller may still decide, each
 * decided in place. Approve asks for a recent sign-in (the API client prompts
 * and retries); the server re-checks the approval policy and four-eyes.
 * Keys, while a row has focus: j / k move, Enter opens the finding, a
 * approves, r rejects.
 */
export function ReviewQueue({
  rows,
  total,
  onChanged,
  toolbar,
  empty,
}: {
  rows: ApiApproval[]
  total: number
  onChanged: () => unknown
  toolbar?: React.ReactNode
  empty: React.ReactNode
}) {
  const { t } = useTranslation()
  const stepUpHint = t(
    'myWork.review.stepUpHint',
    'You confirm your sign-in before the approval is saved.'
  )
  const router = useRouter()
  const currentUserId = useDisplayUser()?.id
  const decision = useApprovalDecision({
    onDecided: () => Promise.all([onChanged(), refreshPendingApprovalCount()]),
  })
  const [focus, setFocus] = useState(0)
  const refs = useRef<(HTMLLIElement | null)[]>([])

  const move = useCallback(
    (to: number) => {
      const i = Math.max(0, Math.min(rows.length - 1, to))
      setFocus(i)
      refs.current[i]?.focus()
    },
    [rows.length]
  )

  const onKeyDown = (e: React.KeyboardEvent<HTMLUListElement>) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return
    const row = rows[focus]
    if (!row) return
    const decidable = !isOwnApproval(row, currentUserId)
    switch (e.key) {
      case 'j':
      case 'ArrowDown':
        e.preventDefault()
        move(focus + 1)
        break
      case 'k':
      case 'ArrowUp':
        e.preventDefault()
        move(focus - 1)
        break
      case 'Enter':
        // Enter on a control in the row (Approve, Reject, a link) is that
        // control's own; only Enter on the row opens the finding.
        if (e.target instanceof HTMLElement && e.target.closest('button, a, input, textarea'))
          return
        e.preventDefault()
        router.push(`/findings/${encodeURIComponent(row.finding_id)}`)
        break
      case 'a':
        if (decidable) {
          e.preventDefault()
          decision.openApprove(row)
        }
        break
      case 'r':
        if (decidable) {
          e.preventDefault()
          decision.openReject(row)
        }
        break
    }
  }

  return (
    <>
      <QueueFrame
        label={t('myWork.tabs.review', 'Awaiting my review')}
        toolbar={toolbar}
        primary={
          rows.length > 0 ? (
            <Button size="sm" onClick={() => decision.openApprove(rows[0])}>
              {t('myWork.review.next', 'Review next')}
            </Button>
          ) : null
        }
        footer={
          <>
            <span>
              {t(
                'myWork.review.fourEyes',
                'Four-eyes: nobody approves their own request, and a risk acceptance always needs a second person.'
              )}
            </span>
            {rows.length > 0 && (
              <span className="hidden md:inline">
                {t(
                  'myWork.review.keys',
                  'j and k move, Enter opens the finding, a approves, r rejects'
                )}
              </span>
            )}
          </>
        }
        shown={rows.length}
        total={total}
      >
        {rows.length === 0 ? (
          empty
        ) : (
          <ul
            className="divide-y"
            onKeyDown={onKeyDown}
            aria-label={t('myWork.tabs.review', 'Awaiting my review')}
          >
            {rows.map((a, i) => {
              const own = isOwnApproval(a, currentUserId)
              const busy = decision.busyId === a.id
              return (
                <ApprovalRow
                  key={a.id}
                  approval={a}
                  currentUserId={currentUserId}
                  focused={focus === i}
                  onFocus={() => setFocus(i)}
                  rowRef={(el) => {
                    refs.current[i] = el
                  }}
                  actions={
                    <QueueDecisionActions
                      name={
                        toDisplayText(a.finding_title, 300) ||
                        t('myWork.untitled', 'Untitled finding')
                      }
                      itemId={a.id}
                      canDecide
                      own={own}
                      ownLabel={t('myWork.review.own', 'Your request: another person decides')}
                      ownReason={t(
                        'findings.approvals.ownRequestHint',
                        'Another approver must decide your own request.'
                      )}
                      busy={busy}
                      onApprove={() => decision.openApprove(a)}
                      onReject={() => decision.openReject(a)}
                      approveLabel={t('myWork.review.approve', 'Approve')}
                      rejectLabel={t('myWork.review.reject', 'Reject')}
                      stepUpHint={stepUpHint}
                    />
                  }
                />
              )
            })}
          </ul>
        )}
      </QueueFrame>
      {decision.dialogs}
    </>
  )
}
