### Security: a request that outlives the request timeout can no longer crash the API

- When a handler set a response header after the request timeout (30 s by
  default) had fired, it wrote to the same header map as the timeout's 504
  response, from another goroutine. That concurrent map write is a fatal Go
  error: the whole API process exited and dropped every in-flight request. A
  member could trigger it, for example with concurrent dashboard overview
  calls on a large tenant.
- The timeout middleware now gives the handler its own header map. The map
  is copied to the response under the writer's lock on the handler's first
  write, and never after a timeout. Late headers and body are dropped, and the
  handler's context is still cancelled at the deadline.
