'use client'

import { useId, useState } from 'react'
import { cn } from '@/lib/utils'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  AlertDialog,
  AlertDialogBody,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'

type ConfirmDialogProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: React.ReactNode
  disabled?: boolean
  desc: React.JSX.Element | string
  cancelBtnText?: string
  confirmText?: React.ReactNode
  destructive?: boolean
  /**
   * Runs the action. When it returns a promise, both buttons stay disabled
   * until it settles, so a second click cannot fire the action twice.
   */
  handleConfirm: () => unknown
  isLoading?: boolean
  className?: string
  children?: React.ReactNode
  /**
   * For actions that cannot be undone: the confirm button stays disabled until
   * the user types this exact text (e.g. the organization's name). Matching is
   * case-sensitive; surrounding spaces and Unicode composition (an input method
   * may type "ế" as e + two combining marks) are ignored. Pasting is allowed.
   */
  typeToConfirm?: string
}

/** True when what the user typed confirms `expected` (see typeToConfirm). */
export function typedTextMatches(typed: string, expected: string): boolean {
  return typed.trim().normalize('NFC') === expected.trim().normalize('NFC')
}

/** Bulk deletes of this many items or more ask the user to type the count. */
export const BULK_TYPE_TO_CONFIRM_MIN = 10

/** The typeToConfirm value for a bulk action: the count once it is large. */
export function bulkTypeToConfirm(count: number): string | undefined {
  return count >= BULK_TYPE_TO_CONFIRM_MIN ? String(count) : undefined
}

/**
 * The typeToConfirm value for an action that cannot be undone on a selection:
 * the item's name when one is selected, otherwise the count. Each item alone
 * would ask for its name, so a selection always asks for something.
 */
export function irreversibleTypeToConfirm(names: readonly string[]): string {
  return names.length === 1 && names[0] ? names[0] : String(names.length)
}

/** How many names ConfirmSample lists before "and N more". */
export const CONFIRM_SAMPLE_SIZE = 5

/**
 * The first few names of the items an action touches, so the user sees what a
 * count stands for before confirming it.
 */
export function ConfirmSample({ names, total }: { names: readonly string[]; total?: number }) {
  const { t } = useTranslation()
  const all = total ?? names.length
  const shown = names.slice(0, CONFIRM_SAMPLE_SIZE)
  if (shown.length === 0) return null
  const more = all - shown.length
  return (
    <div className="rounded-md border bg-muted/40 p-3 text-sm">
      <ul className="space-y-1">
        {shown.map((name, i) => (
          <li key={`${i}-${name}`} className="truncate font-medium" title={name}>
            {name}
          </li>
        ))}
      </ul>
      {more > 0 && (
        <p className="mt-2 text-muted-foreground">
          {t('confirm.sampleMore', 'and {count} more', { count: more })}
        </p>
      )}
    </div>
  )
}

export function ConfirmDialog(props: ConfirmDialogProps) {
  const {
    title,
    desc,
    children,
    className,
    confirmText,
    cancelBtnText,
    destructive,
    isLoading,
    disabled = false,
    handleConfirm,
    typeToConfirm,
    ...actions
  } = props
  const { t } = useTranslation()
  const inputId = useId()
  const [typed, setTyped] = useState('')
  const [running, setRunning] = useState(false)
  const typedOk = !typeToConfirm || typedTextMatches(typed, typeToConfirm)
  const busy = !!isLoading || running
  const [typeBefore, typeAfter = ''] = t('confirm.typeToConfirm', 'Type {text} to confirm').split(
    '{text}'
  )
  const onConfirm = () => {
    if (busy || disabled || !typedOk) return
    const result = handleConfirm()
    if (result && typeof (result as PromiseLike<unknown>).then === 'function') {
      setRunning(true)
      const done = () => setRunning(false)
      ;(result as PromiseLike<unknown>).then(done, done)
    }
  }
  return (
    <AlertDialog
      {...actions}
      onOpenChange={(open) => {
        // Esc and outside clicks do not close it while the action runs.
        if (!open && busy) return
        if (!open) setTyped('')
        actions.onOpenChange(open)
      }}
    >
      <AlertDialogContent className={cn(className)}>
        <AlertDialogHeader className="text-start">
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div>{desc}</div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        {children || typeToConfirm ? (
          <AlertDialogBody className="space-y-4">
            {children}
            {typeToConfirm && (
              <div className="space-y-2">
                <Label htmlFor={inputId} className="block font-normal">
                  {typeBefore}
                  <span className="font-semibold break-all">{typeToConfirm}</span>
                  {typeAfter}
                </Label>
                <Input
                  id={inputId}
                  value={typed}
                  onChange={(e) => setTyped(e.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>
            )}
          </AlertDialogBody>
        ) : null}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>
            {cancelBtnText ?? t('confirm.cancel', 'Cancel')}
          </AlertDialogCancel>
          <Button
            variant={destructive ? 'destructive' : 'default'}
            onClick={onConfirm}
            disabled={disabled || busy || !typedOk}
          >
            {confirmText ?? t('confirm.continue', 'Continue')}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
