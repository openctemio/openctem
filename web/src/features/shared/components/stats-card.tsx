'use client'

import type * as React from 'react'
import Link from '@/components/link'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import type { LucideIcon } from 'lucide-react'
import { Info, TrendingDown, TrendingUp, Minus } from 'lucide-react'

interface StatsCardProps {
  title: string
  value: string | number
  change?: string
  changeType?: 'positive' | 'negative' | 'neutral'
  icon?: LucideIcon
  description?: string
  className?: string
  /** Optional color class for the value, for semantic KPIs (e.g. a red
   *  "Critical" count, a green "Passed"). Omit for the default neutral style. */
  valueClassName?: string
  /** Optional color class for the icon (defaults to muted). */
  iconClassName?: string
  /** Optional definition shown in a tooltip from an info button beside the
   *  title — for metrics whose exact meaning matters (how it is computed). */
  info?: React.ReactNode
  /** Accessible name of the info button. Pass a translated label; the
   *  English default is kept for callers not yet translated. */
  infoLabel?: string
  /** Makes the whole card open this list. The title is the link (a stretched
   *  hit area), so the info button stays a sibling, never nested in the anchor. */
  href?: string
}

export function StatsCard({
  title,
  value,
  change,
  changeType = 'neutral',
  icon: Icon,
  description,
  className,
  valueClassName,
  iconClassName,
  info,
  infoLabel,
  href,
}: StatsCardProps) {
  const changeColors = {
    positive: 'text-success',
    negative: 'text-destructive',
    neutral: 'text-muted-foreground',
  }

  const TrendIcon =
    changeType === 'positive' ? TrendingUp : changeType === 'negative' ? TrendingDown : Minus

  return (
    <Card
      className={cn(
        href &&
          'relative transition-shadow focus-within:ring-2 focus-within:ring-ring hover:shadow-md',
        className
      )}
    >
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <div className="flex min-w-0 items-center gap-1.5">
          <CardTitle className="text-sm font-medium">
            {href ? (
              <Link
                href={href}
                className="after:absolute after:inset-0 after:rounded-xl focus-visible:outline-none"
              >
                {title}
              </Link>
            ) : (
              title
            )}
          </CardTitle>
          {info && (
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  aria-label={infoLabel ?? `How ${title} is measured`}
                  className="relative z-10 shrink-0 rounded-sm text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <Info className="h-3.5 w-3.5" />
                </button>
              </TooltipTrigger>
              <TooltipContent className="max-w-xs text-xs leading-relaxed">{info}</TooltipContent>
            </Tooltip>
          )}
        </div>
        {Icon && <Icon className={cn('h-4 w-4', iconClassName ?? 'text-muted-foreground')} />}
      </CardHeader>
      <CardContent>
        <div className={cn('text-2xl font-bold', valueClassName)}>{value}</div>
        {(change || description) && (
          <div className="flex items-center gap-1">
            {change && (
              <>
                <TrendIcon className={cn('h-3 w-3', changeColors[changeType])} />
                <span className={cn('text-xs', changeColors[changeType])}>{change}</span>
              </>
            )}
            {description && <span className="text-muted-foreground text-xs">{description}</span>}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
