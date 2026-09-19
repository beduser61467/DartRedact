# DartRedact

> Share bug reports, not your secrets.

Local-first scanner and sanitizer for logs, JSON, HAR, environment and YAML files. It detects common credentials and personal data, writes safe copies, and never alters originals or contacts a network service.

## Demo

```text
$ dartredact scan bug-report/
Scanning files...
13 sensitive values detected
CRITICAL ██ 2
HIGH     ████ 4
MEDIUM   ███████ 7

$ dartredact sanitize bug-report/
✓ 13 sensitive values redacted
✓ Original files untouched
✓ Safe report written to ./dartredact-output
```

## Install and use

Requires Dart 3.4+. From this checkout run:

```sh
dart run packages/dart_redact_cli/bin/dartredact.dart scan ./bug-report --json
dart run packages/dart_redact_cli/bin/dartredact.dart sanitize ./bug-report --output ./safe-report --report
```

Supported files: `.txt`, `.log`, `.json`, `.har`, `.env`, `.yaml`, `.yml`. Detectors include GitHub and AWS keys, JWTs, authorization/cookie headers, private keys, generic API keys, URL secret parameters, emails and IPv4/IPv6 addresses.

## Architecture

The CLI depends on `dart_redact_core`; `dart_redact_detectors` supplies small independently-testable detectors. Core has no Flutter or network dependencies, keeping it reusable for future desktop and CI integrations.

## Security

Everything runs locally. Raw secrets are neither printed nor included in reports. Input files are only read; sanitized copies retain directory structure. See [SECURITY.md](SECURITY.md).

## Development

```sh
dart format .
dart analyze
dart test
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [ROADMAP.md](ROADMAP.md), and [AGENTS.md](AGENTS.md).
