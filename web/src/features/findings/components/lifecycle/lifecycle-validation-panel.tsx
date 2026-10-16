'use client'

import { AlertTriangle, CheckCircle2, XCircle } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import type { LifecycleValidationResult } from '../../api/use-finding-lifecycles'

interface LifecycleValidationPanelProps {
  result: LifecycleValidationResult | null
}

/**
 * The validator's answer for a version: errors block publishing, warnings do
 * not. Issue messages are the API's own text (English), with the spec path.
 */
export function LifecycleValidationPanel({ result }: LifecycleValidationPanelProps) {
  const { t } = useTranslation()
  if (!result) {
    return (
      <p className="text-sm text-muted-foreground">
        {t(
          'findingLifecycle.validation.idle',
          'Save the draft or run the check to see whether it can be published.'
        )}
      </p>
    )
  }
  const errors = result.validation.errors ?? []
  const warnings = result.validation.warnings ?? []
  return (
    <div className="space-y-2" aria-live="polite" data-testid="lifecycle-validation">
      {result.valid ? (
        <p className="flex items-center gap-2 text-sm text-success">
          <CheckCircle2 className="size-4" aria-hidden />
          {t('findingLifecycle.validation.valid', 'Ready to publish')}
        </p>
      ) : (
        <p className="flex items-center gap-2 text-sm text-destructive">
          <XCircle className="size-4" aria-hidden />
          {t('findingLifecycle.validation.invalid', '{count} problem(s) to fix before publishing', {
            count: errors.length,
          })}
        </p>
      )}
      {(errors.length > 0 || warnings.length > 0) && (
        <ul className="space-y-1 text-sm">
          {errors.map((i, n) => (
            <li key={`e${n}`} className="flex items-start gap-2">
              <XCircle className="mt-0.5 size-3.5 shrink-0 text-destructive" aria-hidden />
              <span className="min-w-0">
                {i.message}
                {i.path && (
                  <span className="ml-1 font-mono text-xs text-muted-foreground">{i.path}</span>
                )}
              </span>
            </li>
          ))}
          {warnings.map((i, n) => (
            <li key={`w${n}`} className="flex items-start gap-2">
              <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-warning" aria-hidden />
              <span className="min-w-0">
                {i.message}
                {i.path && (
                  <span className="ml-1 font-mono text-xs text-muted-foreground">{i.path}</span>
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
