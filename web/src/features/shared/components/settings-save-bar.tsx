'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { ShortcutKeys } from '@/components/layout/shortcut-keys'
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
  /**
   * The names of the settings that changed ("Organization name", "Time
   * zone"): the bar counts them and lists them under "What changes".
   */
  changes?: readonly string[]
  /** Replaces the count / "You have unsaved changes" (e.g. "2 to enable, 1 to disable"). */
  summary?: string
  /** The last save failed: said in the bar, which stays with the changes kept. */
  error?: string | null
  className?: string
}

/**
 * The one save model of a settings form: a bar pinned to the bottom of the
 * settings column (a full-width bottom bar below 768px), shown only while
 * there are unsaved changes, with what changed, Discard and Save. Ctrl/⌘+S
 * saves. Leaving the page with unsaved changes asks first: the browser's
 * prompt on reload or close, and a dialog on in-app links.
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
  changes,
  summary,
  error,
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

  const count = changes?.length ?? 0
  const text =
    summary ??
    (count > 0
      ? t(
          'settings.saveBar.count',
          '{count, plural, one {# unsaved change} other {# unsaved changes}}',
          { count }
        )
      : t('settings.saveBar.unsaved', 'You have unsaved changes'))

  return (
    <>
      {dirty && (
        <>
          <div
            role="region"
            data-slot="settings-save-bar"
            aria-label={t('settings.saveBar.label', 'Unsaved changes')}
            className={cn(
              'sticky bottom-0 z-20 flex flex-wrap items-center justify-between gap-2 rounded-lg border bg-card px-4 py-3',
              // A phone: the bar spans the screen at its bottom edge.
              'max-md:fixed max-md:inset-x-0 max-md:rounded-none max-md:border-x-0 max-md:border-b-0 max-md:pb-[max(0.75rem,env(safe-area-inset-bottom))]',
              className
            )}
          >
            <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
              <p className="text-body font-medium" aria-live="polite">
                {text}
              </p>
              {count > 0 && (
                <Popover>
                  <PopoverTrigger asChild>
                    <Button type="button" variant="ghost" size="sm">
                      {t('settings.saveBar.what', 'What changes')}
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent side="top">
                    <ul className="list-disc space-y-1 ps-4 text-dense">
                      {changes?.map((c) => (
                        <li key={c}>{c}</li>
                      ))}
                    </ul>
                  </PopoverContent>
                </Popover>
              )}
              {error && (
                <p role="alert" className="basis-full text-cap font-medium text-destructive">
                  {error}
                </p>
              )}
            </div>
            <div className="flex gap-2 max-md:ms-auto">
              <Button type="button" variant="ghost" onClick={onDiscard} disabled={saving}>
                {t('settings.saveBar.discard', 'Discard')}
              </Button>
              <Button
                ref={submitRef}
                type={form ? 'submit' : 'button'}
                form={form}
                onClick={form ? undefined : save}
                disabled={saving || saveDisabled}
                aria-keyshortcuts="Control+S Meta+S"
              >
                {saving && <Loader2 className="animate-spin" aria-hidden />}
                {t('settings.saveBar.save', 'Save changes')}
                <span className="max-md:hidden" aria-hidden>
                  <ShortcutKeys keys={['mod', 'S']} />
                </span>
              </Button>
            </div>
          </div>
          {/* Room under the last section for the fixed bar on a phone. */}
          <div aria-hidden data-slot="settings-save-bar-space" className="h-28 md:hidden" />
        </>
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
