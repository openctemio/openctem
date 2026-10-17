### Security: outbound requests refuse IPv6 site-local addresses

- `pkg/httpsec` now always blocks `fec0::/10` (deprecated IPv6 site-local), which ctis addrscope, the deny list the sensors use, already treats as internal. The security lint rule 6 drift check enforces that the two lists agree.
