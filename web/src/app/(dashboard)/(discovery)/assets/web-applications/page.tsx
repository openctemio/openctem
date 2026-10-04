import { redirect } from 'next/navigation'

export default function Page() {
  // One web sub-type (RFC-042 §6.3.8 O3): web applications are stored as
  // application/website, listed on the websites page.
  redirect('/assets/websites')
}
