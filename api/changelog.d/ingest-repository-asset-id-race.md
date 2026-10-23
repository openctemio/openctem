### Fixed: concurrent uploads to a new repository no longer drop findings

- When several uploads (CI matrix jobs, parallel pipelines) created the same new repository at the same time, the uploads that lost the race on the asset row wrote the repository details under an asset id that was never stored. The foreign key failed and every asset and finding of those uploads was dropped (in a load test, 2 to 7 of 20 uploads). The repository details now use the id the database kept, so every upload attaches its findings to the one stored repository.
