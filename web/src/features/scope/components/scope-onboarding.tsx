'use client'

/**
 * Empty In scope tab (research/53 §4.7): scans refuse every internet target
 * until something is in scope, so the empty state is the three steps to get
 * there. The proof step's wording follows the operator's active-proof mode.
 */

import { Plus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'

export function proofStepText(activeProof: string | undefined): string {
  switch (activeProof) {
    case 'all':
      return 'Required to scan: every active probe needs a verified domain.'
    case 'platform_sensors':
      return "Required for scans on the platform's shared sensors; optional on your own sensors."
    default:
      return 'Optional: it shows your team the domain is proven yours.'
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
  const steps = [
    {
      title: 'Add your domain',
      body: 'Example.com covers example.com and every name below it.',
    },
    {
      title: 'Prove you own it',
      body: `A DNS TXT record, about two minutes. ${proofStepText(activeProof)}`,
    },
    {
      title: 'Discovery finds the rest',
      body: 'Certificate logs and scans find names under it; they join your inventory automatically.',
    },
  ]
  return (
    <Card>
      <CardContent className="space-y-5">
        <div className="space-y-1">
          <h2 className="text-base font-semibold">Nothing is in scope yet</h2>
          <p className="text-sm text-muted-foreground">
            Scans refuse every internet target until a scope entry covers it.
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
            Add your domain
          </Button>
        )}
      </CardContent>
    </Card>
  )
}
