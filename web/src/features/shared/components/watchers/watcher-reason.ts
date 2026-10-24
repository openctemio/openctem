import type { Watcher } from '../../api/use-participants'

type Translate = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

/**
 * Why a person watches, as one sentence-case line for the manage sheet:
 * "Was assigned", "Commented", "Added by Lan Anh", "Added by you".
 */
export function watcherReason(t: Translate, w: Watcher, currentUserId?: string): string {
  switch (w.reason) {
    case 'added':
      if (w.added_by && w.added_by === currentUserId) {
        return t('findings.people.reason.addedByYou', 'Added by you')
      }
      if (w.added_by_name) {
        return t('findings.people.reason.addedBy', 'Added by {name}', { name: w.added_by_name })
      }
      return t('findings.people.reason.added', 'Added by a teammate')
    case 'manual':
      return t('findings.people.reason.manual', 'Chose to watch')
    case 'assigned':
      return t('findings.people.reason.assigned', 'Was assigned')
    case 'commented':
      return t('findings.people.reason.commented', 'Commented')
    case 'status_changed':
      return t('findings.people.reason.status_changed', 'Changed the status')
    case 'fix_claimed':
      return t('findings.people.reason.fix_claimed', 'Claimed the fix')
    case 'mentioned':
      return t('findings.people.reason.mentioned', 'Was mentioned')
    case 'approval':
      return t('findings.people.reason.approval', 'Took part in an approval')
    case 'created':
      return t('findings.people.reason.created', 'Created it')
    default:
      return t('findings.people.reason.other', 'Watching')
  }
}
