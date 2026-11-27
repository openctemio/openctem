import { Button } from '@/components/ui/button'
import { Shield } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'

interface ErrorDisplayProps {
  error: { status?: number; response?: { status?: number } } | null
  onClose: () => void
  onRetry: () => void
}

export function ErrorDisplay({ error: errorDetails, onClose, onRetry }: ErrorDisplayProps) {
  const { t } = useTranslation()
  const status = errorDetails?.status || errorDetails?.response?.status

  const getErrorTitle = () => {
    if (status === 404) return t('org.groupError.notFoundTitle', 'Group not found')
    if (status === 403) return t('org.groupError.forbiddenTitle', 'Access denied')
    if (status && status >= 500) return t('org.groupError.serverTitle', 'Server error')
    return t('org.groupError.loadTitle', 'Failed to load group')
  }

  const getErrorDescription = () => {
    if (status === 404)
      return t(
        'org.groupError.notFound',
        'This group may have been deleted or does not exist in the system.'
      )
    if (status === 403)
      return t(
        'org.groupError.forbidden',
        'You do not have permission to view the details of this group.'
      )
    if (status && status >= 500)
      return t('org.groupError.server', 'A server-side error occurred. Please try again later.')
    return t(
      'org.groupError.load',
      'Failed to load group details. Please check your connection and try again.'
    )
  }

  return (
    <div className="flex flex-col items-center justify-center h-full p-6 text-center space-y-4">
      <div className="rounded-full bg-destructive/10 p-3">
        <Shield className="h-8 w-8 text-destructive" />
      </div>
      <div className="space-y-2">
        <h3 className="font-semibold text-lg">{getErrorTitle()}</h3>
        <p className="text-sm text-muted-foreground max-w-sm">{getErrorDescription()}</p>
      </div>
      <div className="flex gap-2">
        <Button variant="outline" onClick={onClose}>
          {t('common.close', 'Close')}
        </Button>
        <Button onClick={onRetry}>{t('common.retry', 'Retry')}</Button>
      </div>
    </div>
  )
}
