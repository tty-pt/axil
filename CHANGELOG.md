## [1.0.0] - 2026-02-23
- Major architectural refactoring: separated platform-specific code into `ndc-posix.c` and `ndc-win.c` for better maintainability
- Added comprehensive test suite with unit tests, authentication tests, multiplexing tests, and WebSocket protocol tests
- Integrated libndx dependency loading system allowing plugin modules to declare dependencies via `ndx_deps[]`
- Enhanced documentation: expanded README with usage examples, added TypeScript type definitions (`types/ndc.d.ts`), generated Doxygen documentation
- Improved build system: added symbol export maps (`libndc.exports`, `libndc.map`), snapshot-based testing infrastructure
- Added HTTP server-side rendering (SSR) status code support and improved CGI handling
- Fixed multiple build issues for BSD systems and MinGW/Windows platforms
- Added test fixtures for autoindex and CGI functionality

## [0.18.0] - 2025-10-24
- Update to libqmap 0.5.0

## [0.17.0] - 2025-10-19
- Change release strategy
- Headers in ttypt folder
- Autoindex feature
- Auto trailing slash feature
