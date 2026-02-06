# Changelog

All notable changes to this project will be documented in this file.

## [1.5.0] - 2026-02-06

### Added

- **Filesystem Discovery Mode**: New `discover` command to audit the filesystem for orphaned projects not served by Nginx.
- **Web View Report**: Added `--format html` support to generate beautiful, interactive HTML dashboards for both diagnosis and inventory tasks.
- **Output Formats**: Added `--format` flag supporting `rich` (default for TTY), `plain` (text-only, pipe-friendly), `json` (machine-readable), and `html`.
- **Auto-Plain Mode**: Automatically switches to plain text output when redirection or piping is detected.

### Changed

- **Security Check Refinement (NGX200)**: logic for checking `.env` exposure is now smarter. It checks the _effective_ Nginx root and respects explicit `deny` rules, significantly reducing false positives.
- **ReportAction**: Refactored to support pluggable output formats and cleaner separation of concerns.
- **Evidence Formatting**: "Plain" mode ensures evidence references are strictly single-line for easier log parsing.
- **Remediation**: improved generation of remediation commands, particularly for moving backup files (NGX001).

### Fixed

- Fixed an `IndentationError` in `ReportAction`.
- Fixed `NameError` for `contextlib` in CLI.
- Resolved false positives for identifying project roots by strictly correlating with Nginx config.

## [1.4.0] - Previous Version

- Initial release of diagnosis and scanning features.
