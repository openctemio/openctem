'use client'

import { useMemo, useState } from 'react'
import { Check, ChevronRight, Minus } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { cn } from '@/lib/utils'
import { featureCapabilities, useAuthzReference } from '../lib/authz-reference'

interface RoleCapabilitiesProps {
  /** The role's permissions. */
  permissions: readonly string[]
  /** Owner and admin pass every permission check. */
  adminBypass: boolean
}

/**
 * What a role can do in each feature, from the generated authorization
 * reference: how many of the feature's gated actions its permissions pass, and
 * which of the feature's permissions it holds. The same data as the
 * documentation's per-feature pages.
 */
export function RoleCapabilities({ permissions, adminBypass }: RoleCapabilitiesProps) {
  const { reference, unavailable } = useAuthzReference()
  const [open, setOpen] = useState<Set<string>>(new Set())

  const rows = useMemo(
    () => (reference ? featureCapabilities(reference, permissions, adminBypass) : []),
    [reference, permissions, adminBypass]
  )
  const names = useMemo(() => {
    const m = new Map<string, string>()
    for (const p of reference?.permissions ?? []) m.set(p.id, p.name)
    return m
  }, [reference])

  if (unavailable) {
    return (
      <p className="text-sm text-muted-foreground">
        The authorization reference is not available in this build.
      </p>
    )
  }
  if (!reference) {
    return (
      <div className="space-y-2" aria-busy="true">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    )
  }

  const toggle = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  return (
    <div className="space-y-2">
      <p className="text-sm text-muted-foreground">
        {adminBypass
          ? 'Owners and administrators pass every permission check.'
          : 'Actions this role’s permissions allow, by feature. Teams still decide which assets it sees, and a disabled module hides the feature.'}
      </p>
      <ul className="divide-y rounded-md border">
        {rows.map(({ feature, held, allowedRoutes, gatedRoutes }) => {
          const none = allowedRoutes === 0
          const all = gatedRoutes > 0 && allowedRoutes === gatedRoutes
          return (
            <li key={feature.id}>
              <Collapsible open={open.has(feature.id)} onOpenChange={() => toggle(feature.id)}>
                <CollapsibleTrigger className="flex w-full items-center gap-3 px-3 py-2 text-start hover:bg-muted/50">
                  <ChevronRight
                    className={cn(
                      'h-4 w-4 shrink-0 text-muted-foreground transition-transform',
                      open.has(feature.id) && 'rotate-90'
                    )}
                  />
                  <span className={cn('flex-1 text-sm', none && 'text-muted-foreground')}>
                    {feature.title}
                  </span>
                  <Badge
                    variant={all ? 'default' : none ? 'outline' : 'secondary'}
                    className="font-normal tabular-nums"
                  >
                    {allowedRoutes} of {gatedRoutes} actions
                  </Badge>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <div className="space-y-1 px-10 pb-3">
                    <p className="text-xs text-muted-foreground">{feature.description}</p>
                    <ul className="space-y-1 pt-1">
                      {feature.permissions.map((p) => {
                        const has = held.includes(p)
                        return (
                          <li key={p} className="flex items-center gap-2 text-sm">
                            {has ? (
                              <Check className="h-3.5 w-3.5 text-success" aria-label="Held" />
                            ) : (
                              <Minus
                                className="h-3.5 w-3.5 text-muted-foreground"
                                aria-label="Not held"
                              />
                            )}
                            <span className={cn(!has && 'text-muted-foreground')}>
                              {names.get(p) ?? p}
                            </span>
                            <code className="text-xs text-muted-foreground">{p}</code>
                          </li>
                        )
                      })}
                    </ul>
                  </div>
                </CollapsibleContent>
              </Collapsible>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
