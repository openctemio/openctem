'use client'

import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { publishLifecycleVersion, type LifecycleVersion } from '../../api/use-finding-lifecycles'

interface PublishDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  lifecycleId: string
  /** The version to publish: the draft, or an older one to roll back to. */
  version: number
  rollback?: boolean
  onPublished: (v: LifecycleVersion) => void
}

/**
 * Puts a version in force. The API asks for a recent sign-in: the shared API
 * client opens the step-up dialog and retries once, so this dialog only
 * collects the note and shows the outcome. Publishing is audited.
 */
export function PublishDialog({
  open,
  onOpenChange,
  lifecycleId,
  version,
  rollback,
  onPublished,
}: PublishDialogProps) {
  const { t } = useTranslation()
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (open) {
      setNote('')
      setError(null)
    }
  }, [open])

  const submit = async () => {
    setBusy(true)
    setError(null)
    try {
      const v = await publishLifecycleVersion(lifecycleId, version, note.trim() || undefined)
      onPublished(v)
      onOpenChange(false)
    } catch (err) {
      setError(getErrorMessage(err, t('findingLifecycle.publish.failed', 'Could not publish')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>
            {rollback
              ? t('findingLifecycle.publish.rollbackTitle', 'Roll back to version {version}', {
                  version,
                })
              : t('findingLifecycle.publish.title', 'Publish version {version}', { version })}
          </DialogTitle>
          <DialogDescription>
            {rollback
              ? t(
                  'findingLifecycle.publish.rollbackHint',
                  'Version {version} is copied into a new version and put in force. The history stays.',
                  { version }
                )
              : t(
                  'findingLifecycle.publish.hint',
                  'The next status change of every finding this lifecycle applies to follows it. You may be asked to confirm your identity.'
                )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-2">
          <Label htmlFor="publish-note">
            {t('findingLifecycle.publish.note', 'What changed (optional)')}
          </Label>
          <Textarea
            id="publish-note"
            value={note}
            maxLength={500}
            rows={3}
            onChange={(e) => setNote(e.target.value)}
          />
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={submit} disabled={busy}>
            {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {rollback
              ? t('findingLifecycle.publish.rollbackConfirm', 'Roll back')
              : t('findingLifecycle.publish.confirm', 'Publish')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
