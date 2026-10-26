'use client'

import { useCallback, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Lock } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { useDisplayUser } from '@/hooks/use-display-user'
import { refreshPendingApprovalCount } from '@/hooks/use-dynamic-badges'
import { useApprovalDecision } from '@/features/findings/components/approval-decision'
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

  const stepUpHint = t(
    'myWork.review.stepUpHint',
    'You confirm your sign-in before the approval is saved.'
  )

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
                    own ? (
                      <span className="text-meta text-muted-foreground">
                        {t('myWork.review.own', 'Your request: another person decides')}
                      </span>
                    ) : (
                      <>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              size="sm"
                              disabled={busy}
                              onClick={() => decision.openApprove(a)}
                              aria-describedby={`stepup-${a.id}`}
                            >
                              {t('myWork.review.approve', 'Approve')}
                              <Lock className="ms-1.5 size-3.5" aria-hidden="true" />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent className="max-w-xs text-xs">{stepUpHint}</TooltipContent>
                        </Tooltip>
                        <span id={`stepup-${a.id}`} className="sr-only">
                          {stepUpHint}
                        </span>
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={busy}
                          onClick={() => decision.openReject(a)}
                        >
                          {t('myWork.review.reject', 'Reject')}
                        </Button>
                      </>
                    )
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
