'use client'

import { useTranslation } from '@/context/i18n-provider'
import { CheckCircle2, Clock, XCircle } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { VerifiedDomainStatus } from '../types/verified-domain.types'

// Only a failure is coloured; pending and verified stay neutral.
const CONFIG: Record<
  VerifiedDomainStatus,
  { labelKey: string; variant: 'default' | 'outline' | 'destructive'; icon: typeof Clock }
> = {
  pending: { labelKey: 'admin.verifiedDomainStatusBadge.pending', variant: 'outline', icon: Clock },
  verified: {
    labelKey: 'admin.verifiedDomainStatusBadge.verified',
    variant: 'default',
    icon: CheckCircle2,
  },
  failed: {
    labelKey: 'admin.verifiedDomainStatusBadge.failed',
    variant: 'destructive',
    icon: XCircle,
  },
}

export function VerifiedDomainStatusBadge({
  status,
  className,
}: {
  status: VerifiedDomainStatus
  className?: string
}) {
  const { t } = useTranslation()
  const config = CONFIG[status] ?? CONFIG.pending
  const Icon = config.icon
  return (
    <Badge variant={config.variant} className={cn(className)}>
      <Icon />
      {t(config.labelKey)}
    </Badge>
  )
}
