# Contributing

Read `AGENTS.md`, run formatting, analysis and tests before opening a pull request. Keep changes focused and use fake credentials.

To add a detector: implement `SecretDetector`, register it in `defaultDetectors`, then add positive, negative, edge and false-positive tests. Core must remain local-only and dependency-light.
