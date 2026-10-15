### Fixed: creating a remediation campaign works again

- Creating a campaign failed with an internal error after the campaign version column was added (the insert sent one value more than it named). Campaigns are created at version 1.
