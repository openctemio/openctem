'use client'

/**
 * Import a bug-bounty program (RFC-065 §5): paste its scope, preview what
 * the import creates, accept the program's rules and scope, import.
 */

import { useRouter } from 'next/navigation'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader } from '@/features/shared'
import { ProgramForm, importProgram, invalidatePrograms } from '@/features/programs'

export default function NewProgramPage() {
  const { t } = useTranslation()
  const router = useRouter()
  return (
    <Main>
      <PageHeader
        title={t('programs.new.title', 'Import program')}
        description={t(
          'programs.new.description',
          'In-scope targets become scope entries that take effect when you accept the program rules; out-of-scope items stop program entries only, never your own scope.'
        )}
      />
      <ProgramForm
        submitLabel={t('programs.new.submit', 'Accept and import')}
        onSubmit={importProgram}
        onDone={(change) => {
          void invalidatePrograms()
          toast.success(t('programs.new.done', 'Program imported'))
          router.push(`/programs/${change.program.id}`)
        }}
      />
    </Main>
  )
}
