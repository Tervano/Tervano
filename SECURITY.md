# Security policy

Tervano is an early-development administration tool. There is no supported
production release yet. Security fixes target the current `main` branch; older
builds may not receive backports.

## Report a vulnerability

Please do not publish exploit details, tokens, private keys, or personal data in
a public issue. Use **Report a vulnerability** on this repository's GitHub
**Security** page when that private form is available. If it is unavailable,
open a minimal public issue asking maintainers for a private reporting channel,
without including the vulnerability details.

Include the affected version or commit, the impact, and steps to reproduce in an
authorized environment. Maintainers will triage privately, coordinate a fix,
and discuss disclosure with the reporter. Do not test against systems you do not
own or have permission to administer.

The [current security model](docs/security-model.md) lists implemented controls,
known gaps, and trust boundaries. A feature is not production-ready solely
because it appears in a development build.
