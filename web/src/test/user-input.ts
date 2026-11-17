import type { UserEvent } from '@testing-library/user-event'

/**
 * Puts a whole value into a field in one step: focus it, then paste.
 *
 * `user.type` sends one key event per character and React renders after each,
 * so a 25-character value in a dialog costs a few hundred milliseconds, and
 * several seconds on a busy machine. The field ends with the same value and
 * the same change handler runs; use `user.type` only where the keystrokes
 * themselves are under test (a key filter, a shortcut, an Enter submit).
 */
export async function enter(user: UserEvent, field: HTMLElement, text: string): Promise<void> {
  await user.click(field)
  await user.paste(text)
}
