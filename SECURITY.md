# Security Policy

## Reporting a vulnerability in gyrseek

Email **gyrforge@outlook.com**. Please do not open a public issue for a security
report: gyrseek is a security tool, and a flaw in it is useful to the same people
it is meant to stop.

Include whatever you have — the command you ran, the package and version, the
configuration, and what you expected to happen instead. A reproduction helps most,
but a clear description of the weakness is enough to start.

gyrseek is maintained by individuals in their own time, not by a company, so there
is no guaranteed response time and no bounty. Reports are read and acted on as
soon as the maintainers can, and you will be credited in the release notes unless
you ask otherwise.

## Scope

In scope: anything that makes gyrseek clear an install it should have blocked,
report a package as scanned when it was not, allow a payload to escape the probe
container or tamper with its own trace, or leak the credentials of the machine it
runs on.

Out of scope: that gyrseek does not detect a given attack. gyrseek compares a
version against its predecessors inside a sandbox, so it detects *change*, not
malice, and a clear result means only that no new install-time or import-time
behaviour was observed against the baselines. Known limits are documented in
[docs/DETECTION_COVERAGE.md](docs/DETECTION_COVERAGE.md), including whole classes
that are deliberately not covered. If a gap is already written down there, it is
a known limitation rather than a vulnerability — though a report that one of those
limits is *worse* than documented is in scope and welcome.

Vulnerabilities in a package that gyrseek scanned belong with that package's
maintainers or registry, not here.

## Supported versions

Only the latest release. Releases are immutable, so a fix ships as a new version
rather than as a replacement of an existing one. See
[docs/RELEASING.md](docs/RELEASING.md).

## No warranty

gyrseek is provided under the Apache License 2.0, without warranty or conditions
of any kind. See [LICENSE](LICENSE), sections 7 and 8.
