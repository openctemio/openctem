/**
 * The steps of the scan wizard (New scan and Edit scan) and their labels.
 * The step strip itself is the shared one
 * (`features/shared/components/forms/wizard.tsx`). Design: research/418.
 */

export type ScanWizardStep = 'basic' | 'targets' | 'options' | 'schedule' | 'review'

const LABEL_KEYS: Record<ScanWizardStep, string> = {
  basic: 'scans.step.what',
  targets: 'scans.step.targets',
  options: 'scans.step.options',
  schedule: 'scans.step.schedule',
  review: 'scans.step.review',
}

export function stepLabelKey(step: ScanWizardStep): string {
  return LABEL_KEYS[step]
}
