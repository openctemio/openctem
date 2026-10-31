'use client'

import { useEffect, useId, useRef, useState } from 'react'
import { Loader2, Upload } from 'lucide-react'
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
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'

import {
  createWordlist,
  getWordlist,
  invalidateWordlists,
  updateWordlist,
} from '../api/use-wordlists'
import { MAX_WORDLIST_TEXT_BYTES, reportText, utf8Bytes } from '../lib/report'
import type { Wordlist } from '../types'

interface WordlistDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The list to edit; null creates one. */
  wordlist: Wordlist | null
}

/** New list / edit list: name, description, enabled and the labels (typed, pasted or a .txt file). */
export function WordlistDialog({ open, onOpenChange, wordlist }: WordlistDialogProps) {
  const { t } = useTranslation()
  const ids = { name: useId(), description: useId(), enabled: useId(), text: useId() }
  const fileRef = useRef<HTMLInputElement>(null)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [enabled, setEnabled] = useState(true)
  const [text, setText] = useState('')
  const [original, setOriginal] = useState('')
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) return
    setName(wordlist?.name ?? '')
    setDescription(wordlist?.description ?? '')
    setEnabled(wordlist?.enabled ?? true)
    setText('')
    setOriginal('')
    setError(null)
    if (!wordlist) return
    // The list read without labels; the labels come with the single read.
    let live = true
    setLoading(true)
    getWordlist(wordlist.id)
      .then((w) => {
        if (!live) return
        setText(w.content ?? '')
        setOriginal(w.content ?? '')
      })
      .catch((e: unknown) =>
        setError(getErrorMessage(e, t('wordlists.toast.loadFailed', 'Could not load the list')))
      )
      .finally(() => live && setLoading(false))
    return () => {
      live = false
    }
  }, [open, wordlist, t])

  const tooLarge = utf8Bytes(text) > MAX_WORDLIST_TEXT_BYTES

  async function readFile(file: File) {
    if (file.size > MAX_WORDLIST_TEXT_BYTES) {
      setError(t('wordlists.dialog.fileTooLarge', 'The file is larger than 2 MB.'))
      return
    }
    setError(null)
    setText(await file.text())
  }

  async function submit() {
    if (tooLarge) return
    setSaving(true)
    setError(null)
    try {
      const res = wordlist
        ? await updateWordlist(wordlist.id, {
            name: name.trim(),
            description: description.trim(),
            enabled,
            ...(text !== original ? { text } : {}),
          })
        : await createWordlist({
            name: name.trim(),
            description: description.trim(),
            enabled,
            text,
          })
      await invalidateWordlists()
      toast.success(t('wordlists.toast.saved', 'List saved'), {
        description: res.report ? reportText(res.report, t) : undefined,
      })
      onOpenChange(false)
    } catch (e) {
      setError(getErrorMessage(e, t('wordlists.toast.saveFailed', 'Could not save the list')))
    } finally {
      setSaving(false)
    }
  }

  const busy = saving || loading
  return (
    <Dialog open={open} onOpenChange={(o) => !saving && onOpenChange(o)}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>
            {wordlist
              ? t('wordlists.dialog.editTitle', 'Edit list')
              : t('wordlists.dialog.newTitle', 'New list')}
          </DialogTitle>
          <DialogDescription>
            {t(
              'wordlists.dialog.description',
              'Words your organization uses in its host names, one per line. Each is asked of DNS under your domains during subdomain discovery.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogForm
          onSubmit={(e) => {
            e.preventDefault()
            void submit()
          }}
        >
          <DialogBody className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor={ids.name}>{t('wordlists.field.name', 'Name')}</Label>
              <Input
                id={ids.name}
                value={name}
                maxLength={64}
                onChange={(e) => setName(e.target.value)}
                disabled={busy}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor={ids.description}>
                {t('wordlists.field.description', 'Description')}
              </Label>
              <Input
                id={ids.description}
                value={description}
                maxLength={500}
                onChange={(e) => setDescription(e.target.value)}
                disabled={busy}
              />
            </div>
            <div className="flex items-center gap-3">
              <Switch
                id={ids.enabled}
                checked={enabled}
                onCheckedChange={setEnabled}
                disabled={busy}
              />
              <Label htmlFor={ids.enabled}>
                {t('wordlists.field.enabled', 'Use in subdomain discovery')}
              </Label>
            </div>
            <div className="space-y-1.5">
              <div className="flex flex-wrap items-end justify-between gap-2">
                <Label htmlFor={ids.text}>{t('wordlists.field.labels', 'Labels')}</Label>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => fileRef.current?.click()}
                  disabled={busy}
                >
                  <Upload className="size-4" aria-hidden />
                  {t('wordlists.dialog.upload', 'Upload .txt')}
                </Button>
                <input
                  ref={fileRef}
                  type="file"
                  accept=".txt,text/plain"
                  className="sr-only"
                  aria-label={t('wordlists.dialog.upload', 'Upload .txt')}
                  onChange={(e) => {
                    const f = e.target.files?.[0]
                    if (f) void readFile(f)
                    e.target.value = ''
                  }}
                />
              </div>
              <Textarea
                id={ids.text}
                value={text}
                rows={10}
                spellCheck={false}
                className="font-mono text-sm"
                placeholder={t(
                  'wordlists.dialog.placeholder',
                  '# one label per line\nhn01\nportal'
                )}
                onChange={(e) => setText(e.target.value)}
                disabled={busy}
                aria-describedby={`${ids.text}-help`}
              />
              <p id={`${ids.text}-help`} className="text-xs text-muted-foreground">
                {t(
                  'wordlists.dialog.help',
                  'Letters, digits and dashes, up to three dot-separated parts. Lines starting with # are ignored. Lines that are not DNS labels or look like secrets are dropped. Up to 50,000 labels.'
                )}
              </p>
              {tooLarge && (
                <p className="text-xs text-destructive">
                  {t('wordlists.dialog.textTooLarge', 'The text is larger than 2 MB.')}
                </p>
              )}
              {error && (
                <p className="text-xs text-destructive" role="alert">
                  {error}
                </p>
              )}
            </div>
          </DialogBody>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={saving}
            >
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button
              type="submit"
              disabled={busy || tooLarge || name.trim() === '' || (!wordlist && text.trim() === '')}
            >
              {saving && <Loader2 className="size-4 animate-spin" aria-hidden />}
              {t('wordlists.save', 'Save')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
