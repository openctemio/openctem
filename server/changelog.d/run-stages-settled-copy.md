### Fixed: a finished run without a stage plan no longer says its stages are "not planned yet"

- A run that ran its scan's step directly (a quick scan, every continuous coverage run) never records a stage plan, so its Stages section said "No stage of this run has been planned yet" even after the run finished or failed. A finished run now says that no stage plan was recorded for it; a run in progress keeps the "not planned yet" text.
