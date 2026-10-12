import { Lock } from 'lucide-react'
import { Alert, AlertDescription } from '@/components/ui/alert'

interface ReadOnlyNoticeProps {
  /** Why the page is read-only, e.g. "Only administrators can change these settings." */
  reason: string
  className?: string
}

/**
 * Shown on a settings page the caller may read but not change, so the
 * controls are visibly locked instead of failing with 403 on Save.
 */
export function ReadOnlyNotice({ reason, className }: ReadOnlyNoticeProps) {
  return (
    <Alert className={className} role="status">
      <Lock className="h-4 w-4" />
      <AlertDescription>{reason}</AlertDescription>
    </Alert>
  )
}
