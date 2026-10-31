### Security: a sensor whose identity runs on two hosts gets no new work

- When the same sensor key is seen in use from two hosts at once (the existing `identity_cloned` health reason), the platform now withholds new work from that sensor on every claim path and the heartbeat doorbell, instead of only flagging it. Work it already holds finishes normally.
- A waiting task names the reason `identity_cloned` ("Why waiting?"). Re-pair the sensor on the host you keep and stop the other copy; re-pairing (or regenerating a bearer key) clears the flag.
