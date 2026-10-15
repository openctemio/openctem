### Security: program identification is validated as a sensor sends it

- A program's required header values and User-Agent must be printable ASCII when saved; CR, LF and other control characters were already refused. Sensors refuse anything else (sdk-go `OrgHTTPPolicy`, the tool host's boundary check).
- A job whose programs together require more than 10 headers, or whose stored rules predate the ASCII rule, now fails at dispatch with `PROGRAM_RULES_CONFLICT` and the reason. Before, a sensor would refuse it.
