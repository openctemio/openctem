'use client'

/**
 * Empty In scope tab (research/53 §4.7): scans refuse every internet target
 * until something is in scope, so the empty state is the three steps to get
 * there. The proof step's wording follows the operator's active-proof mode.
 */

import { Plus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { useTranslation } from '@/context/i18n-provider'

type Translate = (key: string, fallback?: string) => string

export function proofStepText(activeProof: string | undefined, t?: Translate): string {
  const tr: Translate = t ?? ((_key, fallback) => fallback ?? '')
  switch (activeProof) {
    case 'platform_sensors':
      return tr(
        'scope.onboarding.proofPlatform',
        "Required for scans on the platform's shared sensors; optional on your own sensors."
      )
    default:
      return tr(
        'scope.onboarding.proofOptional',
        'Optional: it shows your team the domain is proven yours.'
      )
  }
}

export function ScopeOnboarding({
  activeProof,
  canAdd,
  onAdd,
}: {
  activeProof?: string
  canAdd: boolean
  onAdd: () => void
}) {
  const { t } = useTranslation()
  const steps = [
    {
      title: t('scope.onboarding.step1.title', 'Add your domain'),
      body: t(
        'scope.onboarding.step1.body',
        'Example.com covers example.com and every name below it.'
      ),
    },
    {
      title: t('scope.onboarding.step2.title', 'Prove you own it'),
      body: t('scope.onboarding.step2.body', 'A DNS TXT record, about two minutes. {proof}', {
        proof: proofStepText(activeProof, t),
      }),
    },
    {
      title: t('scope.onboarding.step3.title', 'Discovery finds the rest'),
      body: t(
        'scope.onboarding.step3.body',
        'Certificate logs and scans find names under it. They join your inventory automatically.'
      ),
    },
  ]
  return (
    <Card>
      <CardContent className="space-y-5">
        <div className="space-y-1">
          <h2 className="text-base font-semibold">
            {t('scope.onboarding.title', 'Nothing is in scope yet')}
          </h2>
          <p className="text-sm text-muted-foreground">
            {t(
              'scope.onboarding.description',
              'Scans refuse every internet target until a scope entry covers it.'
            )}
          </p>
        </div>
        <ol className="grid gap-4 sm:grid-cols-3">
          {steps.map((s, i) => (
            <li key={s.title} className="flex gap-3">
              <span
                aria-hidden
                className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-medium tabular-nums"
              >
                {i + 1}
              </span>
              <span className="min-w-0">
                <span className="block text-sm font-medium">{s.title}</span>
                <span className="block text-sm text-muted-foreground text-pretty">{s.body}</span>
              </span>
            </li>
          ))}
        </ol>
        {canAdd && (
          <Button size="sm" onClick={onAdd}>
            <Plus className="h-4 w-4" />
            {t('scope.onboarding.step1.title', 'Add your domain')}
          </Button>
        )}
      </CardContent>
    </Card>
  )
}
