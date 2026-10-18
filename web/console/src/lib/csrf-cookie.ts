/**
 * The console's own pre-session CSRF cookie. Cookies ignore ports, so on the
 * tenant host's second port the tenant site's `csrf_token` would be shared
 * with (and overwritten by) the console; a name of its own keeps the two
 * double-submit pairs apart.
 */
export const CONSOLE_CSRF_COOKIE = 'console_csrf'
