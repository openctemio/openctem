### Security: profile pictures load only from known avatar hosts

- A profile picture is shown to teammates, so an arbitrary URL could act as a tracking pixel and log their IP addresses and browsers. `PUT /api/v1/users/me` now refuses an `avatar_url` that is not an https URL (no credentials, no port) on a known avatar host: GitHub, Google, Gravatar or GitLab.com (400). An empty value still clears the picture.
- A picture from an identity provider on another host is dropped at account creation (the person shows initials); the sign-in is not affected.
- The web shows a stored picture only when it meets the same rule, so values saved before this change stop loading; commit-author pictures in the repository view follow the same rule.
