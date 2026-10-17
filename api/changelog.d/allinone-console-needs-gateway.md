### Security: the all-in-one image no longer exposes the platform console without the gateway

- With `GATEWAY=off` the console used to listen on `0.0.0.0:3001` without
  forwarding the client address, so the API's admin network check saw
  `127.0.0.1` and allowed every caller. The console now always binds to
  `127.0.0.1` and, with `GATEWAY=off`, is not started unless
  `OPENCTEM_CONSOLE_STANDALONE=true`. Port 3001 is no longer part of the
  published-ports guidance.
