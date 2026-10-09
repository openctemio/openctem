### Security: the sensor pairing start budget groups IPv6 callers by /64

- Starting a pairing (`POST /api/v2/sensor/pairings`, no credentials) is limited per source address, and the number of open pairings is capped platform-wide. One IPv6 host usually holds a whole /64, so a single caller had a practically unlimited number of per-address budgets and could fill the platform-wide cap, which blocked pairing for every organization. IPv6 callers now share one budget per /64.
