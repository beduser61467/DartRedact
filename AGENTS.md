# DartRedact Agent Guide

## Project Summary

DartRedact is a local-first Dart library and CLI for finding and sanitizing sensitive data in developer artifacts before public sharing. It never changes source files, transmits data, or puts raw matches in output/reporting. MVP implements text and structured HAR sanitization.

## Non-Negotiable Rules

* Never modify input files or log/report raw secrets.
* Processing is local: no telemetry, analytics, uploads, or implicit network calls.
* Tests/examples use clearly fake credentials only.
* Fail visibly for unreadable or malformed HAR files; never claim they are safe.
* Avoid dependencies, especially in core.

## Architecture

`dart_redact_cli -> dart_redact_core <- dart_redact_detectors`.

Core owns immutable models, scan orchestration, replacement, file traversal and HAR traversal. Detectors implements independent `SecretDetector`s and a default registry. CLI owns arguments, presentation, reports and exit codes. Core intentionally has no Flutter or network dependencies.

## Important Files

* `packages/dart_redact_core/lib/dart_redact_core.dart` — models, sanitizer, filesystem/HAR support.
* `packages/dart_redact_detectors/lib/dart_redact_detectors.dart` — default detector registry.
* `packages/dart_redact_cli/bin/dartredact.dart` — commands.
* `packages/dart_redact_core/test/` — core/security regression tests.

## Current Implementation Status

DONE: text scanning/redaction; GitHub, AWS, JWT, email, IP, auth, cookie, private key, generic key and URL detectors; recursive scan; copy-only sanitization; HAR structural traversal; Markdown/JSON reports; CLI.
NOT STARTED: entropy detector, Flutter UI, OCR, ZIP/SARIF.

## Current Priorities

1. Run validation once Dart SDK is available.
2. Add release packaging and versioning.

## Architectural Decisions

* Matches retain offsets only in memory; reports expose type/severity/location only.
* Detectors return replacement placeholders, making replacement deterministic and detector-specific.
* HAR is decoded and recursively sanitized by sensitive key names plus normal text scanning, preserving JSON validity.

## Known Issues

* Dart SDK is unavailable in the current environment, so automated validation remains pending.
* YAML is treated as text; it is not parsed/reformatted.

## Commands

`dart format .`
`dart analyze`
`dart test`
`dart run packages/dart_redact_cli/bin/dartredact.dart scan <path>`

## Testing Strategy

Detector tests cover positive/negative cases with fake values. Core tests verify immutable source files, nested output paths and HAR JSON validity. Add false-positive and regression coverage for each detector change.

## Token / Context Efficiency Rules

Read this file, `git status`, and only relevant implementation/tests. Search before opening files; use diffs after edits; do not reread unchanged files or generate large trees. Keep this guide compact and update only material architecture/status changes. Run targeted tests first.

## General Agent Rules

Understand interfaces/tests before edits; minimize scope; preserve APIs; add no speculative abstractions. Never expose secrets in errors. New detectors require positive, negative, edge and false-positive tests. Run format, analysis and relevant tests before completion.

## Last Important Changes

* Initial local-only MVP created with three Dart packages and CLI.
* Initial commit is published to `origin/main`.
* HAR traversal now covers sensitive headers, cookies, query entries, URLs and post data; CLI supports tested `--dry-run`, `--verbose`, and documented exit codes.

## Next Agent Handoff

Run the canonical validation commands after installing Dart. Focus next on release packaging and less common HAR schema coverage; do not redesign the `SecretDetector` API without a compatibility reason.
