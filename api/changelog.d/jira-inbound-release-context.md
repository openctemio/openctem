### Fixed: a Jira delivery whose sender disconnects is processed on retry

- When processing a Jira webhook delivery failed after the sender had
  disconnected, its replay keys were released with the request's canceled
  context, so they stayed held and Jira's retry was dropped as a replay. The
  keys are now released on a context that outlives the request.
