import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import {
  Loader2,
  CheckCircle2,
  XCircle,
  Clock,
  Ban,
  CircleDashed,
  AlertTriangle,
  ShieldAlert,
  type LucideIcon,
} from 'lucide-react'

/**
 * Canonical badge for scan / pipeline RUN status. Replaces the per-page
 * status maps that each rendered a different color set and vocabulary, and
 * the shared StatusBadge which was label-only and collapsed running→active and
 * timeout/canceled→failed. Distinguishes every state with icon + color + label,
 * and animates the running spinner so live runs read at a glance.
 */
type RunStatusConfig = { label: string; icon: LucideIcon; className: string; spin?: boolean }

const RUN_STATUS: Record<string, RunStatusConfig> = {
  queued: { label: 'Queued', icon: CircleDashed, className: 'bg-muted text-muted-foreground' },
  pending: {
    label: 'Pending',
    icon: Clock,
    className: 'bg-warning/15 text-warning',
  },
  running: {
    label: 'Running',
    icon: Loader2,
    className: 'bg-info/15 text-info',
    spin: true,
  },
  completed: {
    label: 'Completed',
    icon: CheckCircle2,
    className: 'bg-success/15 text-success',
  },
  // Kept results but lost some work (a batch or a step failed).
  partial: {
    label: 'Partial',
    icon: AlertTriangle,
    className: 'bg-warning/15 text-warning',
  },
  failed: {
    label: 'Failed',
    icon: XCircle,
    className: 'bg-destructive/15 text-destructive',
  },
  timeout: {
    label: 'Timeout',
    icon: AlertTriangle,
    className: 'bg-warning/15 text-warning',
  },
  canceled: { label: 'Canceled', icon: Ban, className: 'bg-muted text-muted-foreground' },
  // The trigger was refused before anything was dispatched (scope gate,
  // freeze window, no sensor, wildcard target...). Nothing ran.
  blocked: {
    label: 'Blocked',
    icon: ShieldAlert,
    className: 'bg-destructive/10 text-destructive',
  },
}

/**
 * One run's state, everywhere a run state is shown. `progress` (0-100) is
 * added to a live run's label ("Running 42%"); `title` is the hover text
 * (e.g. why a blocked run was refused), rendered as plain text.
 */
export function RunStatusBadge({
  status,
  className,
  progress,
  title,
}: {
  status: string
  className?: string
  progress?: number
  title?: string
}) {
  // Normalize the two spellings the backends use.
  const key = status === 'cancelled' ? 'canceled' : status
  const config = RUN_STATUS[key] ?? {
    label: status ? status.charAt(0).toUpperCase() + status.slice(1) : 'Unknown',
    icon: CircleDashed,
    className: 'bg-muted text-muted-foreground',
  }
  const Icon = config.icon
  const live = key === 'running' || key === 'pending' || key === 'queued'
  const pct =
    live && typeof progress === 'number' && Number.isFinite(progress)
      ? Math.max(0, Math.min(100, Math.round(progress)))
      : null

  return (
    <Badge
      variant="outline"
      title={title}
      className={cn('gap-1 border-transparent font-medium', config.className, className)}
    >
      <Icon className={cn('h-3 w-3', config.spin && 'animate-spin motion-reduce:animate-none')} />
      {config.label}
      {pct !== null && <span className="tabular-nums">{pct}%</span>}
    </Badge>
  )
}
