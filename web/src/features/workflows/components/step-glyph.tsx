import { GitBranch, Play, Send, Zap, type LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { WorkflowNodeType } from '@/lib/api/workflow-types'

// Step kinds are told apart by an icon (its shape), never by colour or a bare
// letter: a bolt for the trigger, a fork for the condition, a play mark for
// the action, a paper plane for the notification (it leaves the platform).
const GLYPH: Record<WorkflowNodeType, LucideIcon> = {
  trigger: Zap,
  condition: GitBranch,
  action: Play,
  notification: Send,
}

/** The glyph of a step kind; decorative, the kind name is always next to it. */
export function StepGlyph({ kind, className }: { kind: string; className?: string }) {
  const Icon = GLYPH[kind as WorkflowNodeType] ?? GLYPH.action
  return (
    <span
      aria-hidden
      data-glyph={kind}
      className={cn(
        'inline-grid size-5 shrink-0 place-items-center text-muted-foreground',
        className
      )}
    >
      <Icon className="size-4" />
    </span>
  )
}
