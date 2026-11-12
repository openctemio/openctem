### Fixed: outbound connections report every address they tried and alternate IPv4 and IPv6

- The SSRF-guarded dialer tried the vetted addresses of a host one after the other but reported only the last failure, so on a network without an IPv6 route a fetch that also failed over IPv4 logged only `connect: network is unreachable` for an IPv6 address, which read as "IPv4 was never tried". The error now names every address and its cause.
- Addresses are tried with the two families alternating (starting with the resolver's first answer), and each attempt but the last is bounded to 4 seconds, so a family a firewall silently drops no longer uses up the request's time before the other family is tried.
- The SSRF check is unchanged: every resolved address is vetted before any connection, and one blocked answer refuses the dial.
