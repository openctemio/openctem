'use client'

import { useState } from 'react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { setToolSourceKey } from '../api/use-tool-sources'
import type { ToolSource } from '../types'
import { validateKeyValue } from '../validation'

interface SetKeyDialogProps {
  source: ToolSource
  open: boolean
  onOpenChange: (open: boolean) => void
  onSaved: () => void
}

export function SetKeyDialog({ source, open, onOpenChange, onSaved }: SetKeyDialogProps) {
  const { t } = useTranslation()
  const [value, setValue] = useState('')
  const [touched, setTouched] = useState(false)
  const [saving, setSaving] = useState(false)
  const rotating = !!source.key?.set
  const error = validateKeyValue(value, source.format)
  const showError = touched && error !== null

  const close = (next: boolean) => {
    if (!next) {
      // The value never outlives the dialog.
      setValue('')
      setTouched(false)
    }
    onOpenChange(next)
  }

  const submit = async () => {
    setTouched(true)
    if (error) return
    setSaving(true)
    try {
      await setToolSourceKey(source.id, value)
      toast.success(t('toolSources.saved', 'Key saved for {name}', { name: source.name }))
      setValue('')
      setTouched(false)
      onOpenChange(false)
      onSaved()
    } catch (err) {
      toast.error(getErrorMessage(err, t('toolSources.saveFailed', 'Could not save the key')))
    } finally {
      setSaving(false)
    }
  }

  const messages: Record<string, string> = {
    empty: t('toolSources.error.empty', 'Enter the key.'),
    whitespace: t('toolSources.error.whitespace', 'The key cannot contain spaces or line breaks.'),
    tooLong: t('toolSources.error.tooLong', 'The key is too long (at most 1024 characters).'),
    pairFormat: t(
      'toolSources.error.pairFormat',
      'Enter two parts joined by one colon, both parts filled in.'
    ),
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>
            {rotating
              ? t('toolSources.dialog.rotateTitle', 'Rotate key for {name}', { name: source.name })
              : t('toolSources.dialog.setTitle', 'Set key for {name}', { name: source.name })}
          </DialogTitle>
          <DialogDescription>
            {t(
              'toolSources.dialog.desc',
              'The key is encrypted and cannot be shown again. Only your organization’s scans use it.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogForm
          onSubmit={(e) => {
            e.preventDefault()
            void submit()
          }}
        >
          <DialogBody className="space-y-2">
            <Label htmlFor="tool-source-key">{t('toolSources.dialog.label', 'Key')}</Label>
            <Input
              id="tool-source-key"
              type="password"
              autoComplete="off"
              spellCheck={false}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onBlur={() => setTouched(true)}
              aria-invalid={showError}
            />
            {source.format === 'pair' && source.format_hint && (
              <p className="text-sm text-muted-foreground">
                {t('toolSources.dialog.pairHint', 'Format: {hint}', { hint: source.format_hint })}
              </p>
            )}
            {showError && error && <p className="text-sm text-destructive">{messages[error]}</p>}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => close(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button type="submit" disabled={saving}>
              {t('toolSources.dialog.save', 'Save key')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
