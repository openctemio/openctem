'use client'

import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useTranslation } from '@/context/i18n-provider'
import { TRIAGE_KEYS, type TriageAction } from '../../lib/triage-keys'
import { Kbd } from './kbd'

export const TRIAGE_ACTION_LABELS: Record<TriageAction, { key: string; fallback: string }> = {
  confirm: { key: 'findings.triageMode.action.confirm', fallback: 'Confirm' },
  falsePositive: {
    key: 'findings.triageMode.action.falsePositive',
    fallback: 'Request false positive',
  },
  accept: { key: 'findings.triageMode.action.accept', fallback: 'Request risk acceptance' },
  assign: { key: 'findings.triageMode.action.assign', fallback: 'Assign' },
  skip: { key: 'findings.triageMode.action.skip', fallback: 'Skip' },
  next: { key: 'findings.triageMode.next', fallback: 'Next finding' },
  prev: { key: 'findings.triageMode.prev', fallback: 'Previous finding' },
  evidence: { key: 'findings.triageMode.action.evidence', fallback: 'Evidence' },
  openPage: { key: 'findings.triageMode.action.openPage', fallback: 'Full page' },
  help: { key: 'findings.triageMode.action.help', fallback: 'All keys' },
  exit: { key: 'findings.triageMode.exit', fallback: 'Exit' },
}

/** Every triage key and what it does (the `?` key). */
export function TriageKeysDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>{t('findings.triageMode.keysTitle', 'Triage keys')}</DialogTitle>
          <DialogDescription>
            {t(
              'findings.triageMode.keysDescription',
              'Keys do nothing while you type in a field or a dialog is open.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <dl className="grid grid-cols-[auto_1fr] items-center gap-x-4 gap-y-2 text-sm">
            {TRIAGE_KEYS.map((k) => (
              <div key={k.action} className="contents">
                <dt>
                  <Kbd decorative={false}>{k.label}</Kbd>
                </dt>
                <dd>
                  {t(TRIAGE_ACTION_LABELS[k.action].key, TRIAGE_ACTION_LABELS[k.action].fallback)}
                </dd>
              </div>
            ))}
          </dl>
        </DialogBody>
      </DialogContent>
    </Dialog>
  )
}
