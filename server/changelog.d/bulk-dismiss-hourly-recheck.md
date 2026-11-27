### Security: the hourly re-authentication of bulk dismiss holds under parallel requests

- Bulk dismiss asks for a recent sign-in after 25 findings an hour. Several requests at the same moment could each see the old count; the hour is now counted again when the dismissals are reserved.
- Docs: none (the limit and its message are unchanged)
