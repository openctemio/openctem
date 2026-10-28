### Fixed: a failed CI job keeps its "failure" conclusion

- The fail-fast step no longer cancels its own workflow run. Cancelling it turned the failing job into "cancelled", so a merge-queue group that failed a test (for example the request budget) looked like a lost runner and was re-queued again and again. In the merge queue it still cancels the group's other runs; on pull requests it cancels nothing.
