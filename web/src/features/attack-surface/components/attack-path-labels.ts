'use client'

import { useMemo } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { getAssetTypeLabel } from '@/features/assets/lib/asset-type-icon'
import type { PathBasis, PathNode } from '../hooks/use-attack-path-detail'
import { formatWeight, stepText } from '../lib/attack-path-model'

/** Every text of the attack-path view that depends on a node, in one place. */
export function useAttackPathLabels() {
  const { t } = useTranslation()
  return useMemo(() => {
    const assetType = (type: string) => t(`assets.typeLabel.${type}`, getAssetTypeLabel(type))
    const role = (n: Pick<PathNode, 'role' | 'isCrownJewel'>) =>
      n.role === 'entry'
        ? t('prioritization.attackPath.role.entry', 'Entry point')
        : n.role === 'target'
          ? n.isCrownJewel
            ? t('prioritization.attackPath.role.crownJewel', 'Crown jewel')
            : t('prioritization.attackPath.role.target', 'Target')
          : t('prioritization.attackPath.role.hop', 'Hop')
    const hiddenTitle = t('prioritization.attackPath.hidden', 'Outside your access')
    const basis = (b: PathBasis | null) =>
      b === 'epss'
        ? t('prioritization.attackPath.basis.epss', 'EPSS')
        : b === 'kev'
          ? t('prioritization.attackPath.basis.kev', 'Known exploited')
          : b === 'severity'
            ? t('prioritization.attackPath.basis.severity', 'Severity')
            : b === 'assumed'
              ? t('prioritization.attackPath.basis.assumed', 'Assumed, no open finding')
              : ''
    const nodeDescription = (n: PathNode) => {
      if (n.hidden) return ''
      const step = stepText(n)
      return t('prioritization.attackPath.aria.node', 'Step weight {weight}, {basis}{step}', {
        weight: formatWeight(n.weight),
        basis: basis(n.basis),
        step: step ? t('prioritization.attackPath.aria.through', ', through {step}', { step }) : '',
      })
    }
    const canvasHelp = t(
      'prioritization.attackPath.canvasHelp',
      'Tab moves into the graph. Arrow keys follow the edges: right to the next step, left to the previous one, up and down within a column. Square brackets switch the selected path. Enter opens the findings of a step. Escape clears the highlight.'
    )
    return { assetType, role, hiddenTitle, basis, nodeDescription, canvasHelp }
  }, [t])
}
