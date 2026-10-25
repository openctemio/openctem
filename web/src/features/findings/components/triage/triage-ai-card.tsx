'use client'

/**
 * The finding's latest AI triage as an advisory card. AI never decides:
 * when the model thinks the finding is a false positive, "Apply" only opens
 * the false positive request with the model's reason in the note, and a
 * person reviews and sends it. The text is the model's output: untrusted,
 * rendered as text.
 */

import { Sparkles } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { useTriageResult } from '@/features/ai-triage/api'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import { toDisplayText } from '@/lib/untrusted-text'

/** From this likelihood the card suggests a false positive request. */
export const AI_FP_SUGGESTION_MIN = 0.6

export function TriageAiCard({
  findingId,
  canRequest,
  onApplyFalsePositive,
}: {
  findingId: string
  canRequest: boolean
  /** Opens the false positive request with this note filled in. */
  onApplyFalsePositive: (note: string) => void
}) {
  const { t } = useTranslation()
  // No request without the module (and the hook sends none without ai_triage:read).
  const enabled = useModuleEnabled('ai_triage')
  const { data } = useTriageResult(enabled ? findingId : null)
  if (!data || data.status !== 'completed') return null
  const fpLikelihood = data.falsePositiveLikelihood ?? 0
  const suggestsFp = fpLikelihood >= AI_FP_SUGGESTION_MIN
  const note = toDisplayText(data.falsePositiveReason || data.summary || '', 2000)
  return (
    <section
      aria-labelledby="triage-ai-title"
      className="space-y-2 rounded-lg border bg-card p-4"
      data-testid="triage-ai-card"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 id="triage-ai-title" className="flex items-center gap-1.5 text-sm font-medium">
          <Sparkles className="h-4 w-4" aria-hidden />
          {t('findings.triageMode.ai.title', 'AI suggestion, advisory')}
        </h3>
        <span className="text-xs text-muted-foreground">
          {t(
            'findings.triageMode.ai.policy',
            'Model and data policy are set by your organization.'
          )}
        </span>
      </div>
      {data.summary && (
        <p dir="auto" className="line-clamp-4 text-sm [unicode-bidi:isolate]">
          {toDisplayText(data.summary, 1000)}
        </p>
      )}
      <p className="text-sm font-medium">
        {suggestsFp
          ? t(
              'findings.triageMode.ai.suggestsFp',
              'Suggests: request false positive ({likelihood}% likely).',
              { likelihood: Math.round(fpLikelihood * 100) }
            )
          : t(
              'findings.triageMode.ai.suggestsReal',
              'Suggests: likely real. Confirm if you agree.'
            )}
      </p>
      {suggestsFp && (
        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={!canRequest}
            onClick={() => onApplyFalsePositive(note)}
          >
            {t('findings.triageMode.ai.apply', 'Apply suggestion')}
          </Button>
          <span className="text-xs text-muted-foreground">
            {t(
              'findings.triageMode.ai.applyHint',
              'Fills the request form. Nothing changes until you send it.'
            )}
          </span>
        </div>
      )}
    </section>
  )
}
