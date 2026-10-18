'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Loader2, Save } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { useUnsavedChangesGuard } from '@/hooks/use-unsaved-changes-guard'
import { cn } from '@/lib/utils'

export interface SettingsSaveBarProps {
  /** Unsaved changes exist: the bar shows and leaving the page asks first. */
  dirty: boolean
  /** A save is running. */
  saving?: boolean
  /** Save the changes (a button click or Ctrl/⌘+S). */
  onSave?: () => void
  /** Drop the changes and show the saved values again. */
  onDiscard: () => void
  /** Submit this form id instead of calling onSave (a page that owns a <form>). */
  form?: string
  /** Save is refused (e.g. invalid input); the bar stays, the button is disabled. */
  saveDisabled?: boolean
  /** Replaces "You have unsaved changes" (e.g. "2 to enable · 1 to disable"). */
  summary?: string
  className?: string
}

/**
 * The one save model of a settings form: a bar pinned to the bottom of the
 * content column, shown only while there are unsaved changes, with Discard
 * and Save. Ctrl/⌘+S saves. Leaving the page with unsaved changes asks first:
 * the browser's prompt on reload or close, and a dialog on in-app links.
 *
 * A setting that applies the moment it is switched (no form) does not use the
 * bar: it confirms when it loosens protection and says that it applies at once.
 */
export function SettingsSaveBar({
  dirty,
  saving = false,
  onSave,
  onDiscard,
  form,
  saveDisabled = false,
  summary,
  className,
}: SettingsSaveBarProps) {
  const { t } = useTranslation()
  const router = useRouter()
  const [leaveTo, setLeaveTo] = useState<string | null>(null)
  const submitRef = useRef<HTMLButtonElement>(null)

  useUnsavedChangesGuard(dirty, setLeaveTo)

  const save = useCallback(() => {
    if (saving || saveDisabled) return
    if (form) submitRef.current?.click()
    else onSave?.()
  }, [form, onSave, saving, saveDisabled])

  useEffect(() => {
    if (!dirty) return
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === 's') {
        e.preventDefault()
        save()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [dirty, save])

  return (
    <>
      {dirty && (
        <div
          role="region"
          aria-label={t('settings.saveBar.label', 'Unsaved changes')}
          className={cn(
            'sticky bottom-4 z-20 mt-5 flex flex-wrap items-center justify-between gap-3 rounded-xl border bg-card px-4 py-3 shadow-lg',
            className
          )}
        >
          <p className="text-sm text-muted-foreground" aria-live="polite">
            {summary ?? t('settings.saveBar.unsaved', 'You have unsaved changes')}
          </p>
          <div className="flex gap-2">
            <Button type="button" variant="outline" size="sm" onClick={onDiscard} disabled={saving}>
              {t('settings.saveBar.discard', 'Discard')}
            </Button>
            <Button
              ref={submitRef}
              type={form ? 'submit' : 'button'}
              form={form}
              size="sm"
              onClick={form ? undefined : save}
              disabled={saving || saveDisabled}
              aria-keyshortcuts="Control+S Meta+S"
            >
              {saving ? (
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
              ) : (
                <Save className="h-4 w-4" aria-hidden />
              )}
              {t('settings.saveBar.save', 'Save changes')}
            </Button>
          </div>
        </div>
      )}
      <ConfirmDialog
        open={leaveTo !== null}
        onOpenChange={(open) => !open && setLeaveTo(null)}
        destructive
        title={t('settings.saveBar.leaveTitle', 'Leave without saving?')}
        desc={t(
          'settings.saveBar.leaveDesc',
          'Your changes on this page are not saved. If you leave, they are lost.'
        )}
        cancelBtnText={t('settings.saveBar.stay', 'Stay on this page')}
        confirmText={t('settings.saveBar.leave', 'Leave and discard')}
        handleConfirm={() => {
          const to = leaveTo
          setLeaveTo(null)
          onDiscard()
          if (to) router.push(to)
        }}
      />
    </>
  )
}
