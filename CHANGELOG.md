# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-10

- Static heuristic file risk scanner and CLI (no runtime dependencies): active content, macros, exploit building blocks, archive tricks and type spoofing.
- Supports common office, PDF, RTF, CFB/OLE, ZIP/OOXML/ODF, TAR/GZIP, image and shortcut formats without executing or rendering input.
- Structured findings with rule ids, severity and evidence offsets; library API and `file-sentinel` CLI.
- Works in Node.js; ESM and CJS builds with TypeScript types.

[Unreleased]: https://github.com/gildor853/file-sentinel/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/gildor853/file-sentinel/releases/tag/v1.0.0
