import { cn } from '@/lib/utils'
import type { WorkflowNodeType } from '@/lib/api/workflow-types'

// Step kinds are told apart by a small labelled neutral glyph (its shape and
// letter), never by colour: circle trigger, diamond condition, square action,
// tab-shaped notification (it leaves the platform).
const GLYPH: Record<WorkflowNodeType, { letter: string; shape: string }> = {
  trigger: { letter: 'T', shape: 'rounded-full' },
  condition: { letter: '?', shape: 'rotate-45 scale-[0.82] rounded-[2px]' },
  action: { letter: 'A', shape: 'rounded-[3px]' },
  notification: { letter: 'N', shape: 'rounded-s-[3px] rounded-e-lg' },
}

/** The glyph of a step kind; decorative, the kind name is always next to it. */
export function StepGlyph({ kind, className }: { kind: string; className?: string }) {
  const g = GLYPH[kind as WorkflowNodeType] ?? GLYPH.action
  return (
    <span
      aria-hidden
      data-glyph={kind}
      className={cn(
        'inline-grid size-4 shrink-0 place-items-center border border-foreground/40 text-[9px] leading-none font-semibold text-muted-foreground',
        g.shape,
        className
      )}
    >
      <span className={cn(kind === 'condition' && '-rotate-45')}>{g.letter}</span>
    </span>
  )
}
