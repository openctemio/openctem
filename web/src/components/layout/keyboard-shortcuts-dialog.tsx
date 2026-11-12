'use client'

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { ShortcutKeys } from './shortcut-keys'
import { useTranslation } from '@/context/i18n-provider'
import {
  KEYBOARD_SHORTCUT_GROUPS,
  shortcutsForShell,
  type KeyboardShortcut,
  type ShortcutShell,
} from '@/config/keyboard-shortcuts'

interface KeyboardShortcutsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Lists only what works in this shell. */
  shell: ShortcutShell
}

/** Help > Keyboard shortcuts: the shortcuts in src/config/keyboard-shortcuts.ts. */
export function KeyboardShortcutsDialog({
  open,
  onOpenChange,
  shell,
}: KeyboardShortcutsDialogProps) {
  const { t } = useTranslation()
  const shortcuts = shortcutsForShell(shell)
  const groups = (Object.keys(KEYBOARD_SHORTCUT_GROUPS) as KeyboardShortcut['group'][])
    .map((group) => ({ group, items: shortcuts.filter((s) => s.group === group) }))
    .filter((g) => g.items.length > 0)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('help.shortcuts', 'Keyboard shortcuts')}</DialogTitle>
          <DialogDescription>
            {t('help.shortcuts.description', 'Work faster without leaving the keyboard.')}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-5">
            {groups.map(({ group, items }) => (
              <section key={group} aria-labelledby={`shortcut-group-${group}`}>
                <h3 id={`shortcut-group-${group}`} className="mb-2 text-sm font-semibold">
                  {t(`help.shortcutGroup.${group}`, KEYBOARD_SHORTCUT_GROUPS[group])}
                </h3>
                <ul className="divide-y rounded-md border">
                  {items.map((s) => (
                    <li
                      key={s.id}
                      data-shortcut={s.id}
                      className="flex items-center justify-between gap-4 px-3 py-2 text-sm"
                    >
                      <span>{t(`help.shortcut.${s.id}`, s.label)}</span>
                      <ShortcutKeys keys={s.keys} />
                    </li>
                  ))}
                </ul>
              </section>
            ))}
          </div>
        </DialogBody>
      </DialogContent>
    </Dialog>
  )
}
