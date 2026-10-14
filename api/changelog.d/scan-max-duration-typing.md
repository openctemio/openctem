### Fixed: typing a scan's max duration or retry backoff

- The New and Edit scan wizards clamped the max duration and the retry backoff on every keystroke, so typing 3600 saved 30600 and typing 120 saved 1020. The fields now keep what you type and apply the limits when you leave the field.
