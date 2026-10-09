### Security: one sensor holds at most 8 calls in flight on the v3 gRPC binding

- On the gRPC (mTLS) binding a message of up to 17 MiB is read and decompressed before the per-sensor rate budget applies. One sensor could open many streams and have all of them buffering full-size messages at once.
- The sensor's identity is known from its certificate before the body is read. At that point the binding now admits at most 8 unary calls per sensor per replica; beyond that it answers `503` with `Retry-After`.
- Control streams are not counted; they keep their own limit of 4 per sensor.
