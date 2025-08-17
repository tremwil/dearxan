# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.3.0] - 2025-08-17

### Breaking Changes
- the FFI API and most `dearxan::disabler` functions have had major API changes to support process-wide synchronization. Refer to the docs for updated usage examples.

### Changed
- Process-wide synchronization of `dearxan::disabler::neuter_arxan` by @Dasaav-dsv. This ensures that your callback will be invoked after Arxan has been patched, no matter if other DLL mods using the library have already called it.

### Fixed
- Relocs being applied over disabler patches even when unnecessary

## [v0.2.2] - 2025-08-12

### Fixed
- Missing overflow checks in memory emulation code causing panics in debug builds by @Dasaav-dsv

## [v0.2.1] - 2025-08-08

### Changed
- Improved parallelization of stub analysis and patch generation by @Dasaav-dsv

### Fixed
- Missing `--check` argument to `cargo fmt` in CI
- Incorrect signature `dearxan_neuter_arxan` in the provided include file
- Fix UB on the rust side of `dearxan_neuter_arxan` when the user passes a null callback by @Dasaav-dsv

## [v0.2.0] - 2025-08-07

### Added
- `dearxan::analysis::is_arxan_hooked_entry_point` to check if the entry point of the executable image is hooked by Arxan

### Fixed
- Missing text in readme
- `dearxan::disabler::schedule_after_arxan` not properly checking if Arxan was applied to the entry point (thanks @Dasaav-dsv for raising this issue)

### Removed
- `dearxan::disabler::is_arxan_entry`. Use `dearxan::analysis::is_arxan_hooked_entry_point` instead.

### Changed
- Hardcoded game executable paths for game aliases in `test_launcher` to prevent it detecting a different executable if many are present.

## [v0.1.2] - 2025-08-07

### Fixed
- Added missing credits to @Dasaav-dsv for helping reverse engineer how Arxan decrypts game functions at runtime

## [v0.1.1] - 2025-08-07

### Fixed
- CI release workflow
- Missing `internal_api` feature in readme

## [v0.1.0] - 2025-08-06

Initial release.
