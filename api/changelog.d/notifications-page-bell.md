### Fixed: Notifications page and bell

- An unread notification with a link opens on the first click; it is marked read in the background.
- Notification links only open same-origin paths. A target from an integration or webhook that points off-site (absolute, protocol-relative or `javascript:` URL) shows as a row without a link.
- The bell shows an error with Retry instead of "all caught up" when the list fails to load, rows without a link can be opened from the keyboard, and the bell button names the unread count.
- Failed mark-as-read actions show an error toast on the page and in the bell.
- Every string is translated (English and Vietnamese), times follow the app language, and severity uses the shared badge. The three summary tiles are replaced by an unread count next to "Mark all as read".
