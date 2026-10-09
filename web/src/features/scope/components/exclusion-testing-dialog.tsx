'use client'

/**
 * Change how a path exclusion may be tested (RFC-056 §5), in two steps:
 * choose (Blocked / Read-only / Allowed, an optional end, required for
 * Allowed), then review what changes before it applies. Never an inline
 * toggle. The API needs the exclusion-approve permission and step-up (the
 * shared client asks), audits the change and notifies every administrator.
 * It never widens scope: hosts outside the organization's scope stay
 * refused, and there is no switch that lifts every exclusion at once.
 */

import { useEffect, useId, useState } from 'react'
import { AlertTriangle, ChevronLeft, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { invalidateScopeCache, setScopeExclusionTesting } from '../api/use-scope-api'
import type { ExclusionTesting } from '../api/scope-api.types'
import { scopeErrorMessage } from '../lib/scope-codes'
import {
  effectiveTesting,
  MAX_TESTING_DAYS,
  pathRuleLabel,
  TESTING_HINT,
  TESTING_LABEL,
  testingImpact,
  testingProblem,
  type PathExclusion,
} from '../lib/path-exclusion'
import { daysFromNow } from './scope-exclusion-dialog'
import { ScopeChangePreview } from './scope-change-preview'

const MODES: ExclusionTesting[] = ['blocked', 'read_only', 'allowed']

export function ExclusionTestingDialog({
  exclusion,
  onOpenChange,
}: {
  exclusion: PathExclusion | null
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const id = useId()
  const [mode, setMode] = useState<ExclusionTesting>('blocked')
  const [days, setDays] = useState('')
  const [step, setStep] = useState<'choose' | 'review'>('choose')
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (!exclusion) return
    setMode(effectiveTesting(exclusion))
    setDays('')
    setStep('choose')
    setError(null)
  }, [exclusion])

  if (!exclusion) return null
  const current = effectiveTesting(exclusion)
  const rule = pathRuleLabel(exclusion)
  const n = days.trim() ? Number(days) : null

  const next = () => {
    const problem = testingProblem(mode, n)
    if (problem) return setError(problem)
    if (mode === current && n === null)
      return setError('Choose a different mode or set an end date.')
    setError(null)
    setStep('review')
  }

  const apply = async () => {
    setSaving(true)
    try {
      await setScopeExclusionTesting(exclusion.id ?? '', {
        testing: mode,
        ...(n !== null && mode !== 'blocked' ? { testing_until: daysFromNow(n) } : {}),
      })
      await invalidateScopeCache()
      toast.success(`${rule}: ${TESTING_LABEL[mode].toLowerCase()}`, {
        description: 'Every administrator was notified.',
      })
      onOpenChange(false)
    } catch (err) {
      setError(scopeErrorMessage(t, err, 'The testing mode was not changed.'))
      setStep('choose')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{step === 'choose' ? 'Testing mode' : 'Review change'}</DialogTitle>
          <DialogDescription>
            <code className="break-all">{rule}</code> stays out of scope; this decides what scans
            may still send to it.
          </DialogDescription>
        </DialogHeader>

        <DialogBody>
          <div className="space-y-4">
            {error && (
              <div
                role="alert"
                className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
              >
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}
            {step === 'choose' ? (
              <>
                <RadioGroup
                  value={mode}
                  onValueChange={(v) => {
                    setMode(v as ExclusionTesting)
                    setError(null)
                  }}
                  className="gap-2"
                >
                  {MODES.map((m) => (
                    <label
                      key={m}
                      htmlFor={`${id}-${m}`}
                      className={cn(
                        'flex cursor-pointer items-start gap-3 rounded-md border p-3',
                        'has-[[data-state=checked]]:border-primary has-[[data-state=checked]]:bg-primary/5'
                      )}
                    >
                      <RadioGroupItem id={`${id}-${m}`} value={m} className="mt-0.5" />
                      <span className="min-w-0">
                        <span className="block text-sm font-medium">
                          {TESTING_LABEL[m]}
                          {m === current ? ' (now)' : ''}
                        </span>
                        <span className="block text-xs text-muted-foreground">
                          {TESTING_HINT[m]}
                        </span>
                      </span>
                    </label>
                  ))}
                </RadioGroup>
                {mode !== 'blocked' && (
                  <div className="space-y-2">
                    <Label htmlFor={`${id}-days`}>
                      Back to blocked after (days{mode === 'allowed' ? '' : ', optional'})
                    </Label>
                    <Input
                      id={`${id}-days`}
                      type="number"
                      min={1}
                      max={MAX_TESTING_DAYS}
                      value={days}
                      onChange={(e) => {
                        setDays(e.target.value)
                        setError(null)
                      }}
                      className="w-28"
                    />
                    <p className="text-xs text-muted-foreground">1 to {MAX_TESTING_DAYS} days.</p>
                  </div>
                )}
              </>
            ) : (
              <ScopeChangePreview
                lines={[
                  {
                    key: 'testing',
                    mark: 'change',
                    pattern: rule,
                    summary: `testing ${TESTING_LABEL[current].toLowerCase()} → ${TESTING_LABEL[mode].toLowerCase()}${n !== null && mode !== 'blocked' ? ` for ${n} ${n === 1 ? 'day' : 'days'}` : ''}`,
                    message: testingImpact(current, mode, rule, exclusion.methods),
                  },
                ]}
                consequence={{ approvalsRequired: 0, stepUp: mode !== 'blocked' }}
              />
            )}
            {step === 'review' && (
              <p className="text-xs text-muted-foreground">
                Audited; every administrator is notified. There is no switch that lifts every
                exclusion at once.
              </p>
            )}
          </div>
        </DialogBody>

        <DialogFooter>
          {step === 'review' ? (
            <>
              <Button variant="ghost" onClick={() => setStep('choose')} disabled={saving}>
                <ChevronLeft className="h-4 w-4" />
                Back
              </Button>
              <Button onClick={() => void apply()} disabled={saving}>
                {saving && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
                {mode === 'blocked' ? 'Block testing' : 'Change testing mode'}
              </Button>
            </>
          ) : (
            <>
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button onClick={next}>Review</Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
