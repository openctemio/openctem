import type { Translate } from '@/features/scans/lib/translate'

const ICON_VALUES = [
  ['zap', 'Zap'],
  ['code', 'Code'],
  ['package', 'Package'],
  ['globe', 'Globe'],
  ['key', 'Key'],
  ['server', 'Server'],
  ['box', 'Box'],
  ['search', 'Search'],
  ['layers', 'Layers'],
  ['shield', 'Shield'],
  ['lock', 'Lock'],
  ['eye', 'Eye'],
  ['file-text', 'File text'],
  ['terminal', 'Terminal'],
  ['cpu', 'CPU'],
] as const

/** Icon choices of the capability forms; labels follow the language. */
export function getIconOptions(t: Translate) {
  return ICON_VALUES.map(([value, fallback]) => ({
    value,
    label: t(`scans.capabilities.icon.${value}`, fallback),
  }))
}

/** Category choices of the capability forms; labels follow the language. */
export function getCategoryOptions(t: Translate) {
  return [
    { value: 'security', label: t('scans.capabilities.categoryOption.security', 'Security') },
    { value: 'recon', label: t('scans.capabilities.categoryOption.recon', 'Reconnaissance') },
    { value: 'analysis', label: t('scans.capabilities.categoryOption.analysis', 'Analysis') },
  ]
}
