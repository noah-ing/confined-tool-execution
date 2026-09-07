# Security policy

## Private reporting

Do not publish suspected vulnerability details in an issue. Use **Security → Report a vulnerability** when GitHub's private reporting option is available. GitHub documents its [private reporting procedure](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately).

If private reporting is unavailable, open an issue containing only a request for a private contact channel. Include no sensitive details, credentials, or operational denial records in that public request. This repository publishes no alternative security contact address.

A private report should identify the affected commit, Linux and library versions, required privileges, the supported configuration, observed impact, and a minimal safe regression test where appropriate. Reports concerning another project should follow that project's private reporting policy.

## Support boundary

This is an independent reference implementation, not a production sandbox or a general native-code isolation system. The [scope](docs/scope.md) and [threat model](docs/threat_model.md) define the supported fixed-handler boundary. There is no bug-bounty program, response-time service-level agreement, or production support commitment.

Examples use generated files and loopback listeners. Operational credentials, private upstream findings, and unrelated confidential material must not be included in public fixtures or reports.
