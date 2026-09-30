# Security status

UBC is experimental. The repository is not a security audit or a production authorization service. Do not connect real payments, private customer records or physical actuators to the prototype.

The experimental development profile documents known boundaries, including key storage, persistent replay protection on devices, recovery, address/key pinning, custody forks and relay metadata. The original v0.1 envelope must not authorize business transactions or device control because its legacy signature does not bind every header field.

For a suspected vulnerability, use GitHub private vulnerability reporting if it is enabled for this repository, or arrange a private reporting channel with the maintainer before sending sensitive details. Do not publish real credentials, customer data or live exploit targets in public issues. A reporting channel and response policy must be finalized before a production release.
