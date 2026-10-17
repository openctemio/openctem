### Added: administrators are told when a renamed repository no longer matches its CI trust configuration

- When a repository is renamed on its code host and no CI trust configuration admits the new name, its uploads are refused. The organization's owners and administrators now get an in-app notification and an e-mail with the old and new name and a link to the trust settings. The trust configuration itself is never changed by the platform. One alert per repository and new name per day.
