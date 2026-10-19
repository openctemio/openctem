'use client'

import { useParams } from 'next/navigation'
import { Main } from '@/components/layout'
import { CampaignDetail } from '@/features/remediation/components/campaign-detail'

export default function RemediationCampaignPage() {
  const params = useParams()
  const id = params.id as string
  return (
    <Main>
      <CampaignDetail campaignId={id} />
    </Main>
  )
}
