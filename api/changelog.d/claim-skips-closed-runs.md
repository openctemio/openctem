### Fixed: a canceled or timed-out run hands out no more work

- Canceling or timing out a run cancels the commands that exist at that moment, but a step that finished just before could still create the next step's commands afterwards, and a sensor then scanned for a run the user had stopped. Every claim (poll, claim by id, batch claim, shared sensors) now skips a command whose scan run, in the command's tenant, has ended.
