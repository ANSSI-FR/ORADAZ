# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.05.26] - 2025-05-26

### Added/Changed

- Update schema to add PIM for groups APIs that require new permissions

## [2.0.04.14] - 2025-04-14

### Fixed

- Temporary bugfix for thread termination while a new authentication is required

## [2.0.01.28] - 2025-01-28

### Added/Changed

- Add ORADAZ version in first log to help debugging

## [2.0.01.27] - 2025-01-27

### Fixed

- Use FolderId instead of Identity in exchange_mailboxes_folders_permissions API to avoid invalid characters

## [2.0.01.23] - 2025-01-22

### Added/Changed

- Add Exchange mailbox folders permissions dump

## [2.0.01.22] - 2025-01-21

### Added/Changed

- Add missing log on writer for debugging purposes

## [2.0.01.21] - 2025-01-21

### Added/Changed

- Complete rework of ORADAZ

## [1.2.07.24] - 2024-07-24

### Fixed

- Concurrent write

## [1.1.12.06] - 2023-12-06

### Fixed

- Réauthentication process when a token is expired

## [1.1.02.23] - 2023-02-23

### Fixed

- Role check in prerequisites when role attribution is made on a user group

## [1.1.02.02] - 2023-02-02

### Added/Changed

- Support for unauthenticated proxy
- Support for Basic authentication based proxy

### Fixed

- Ask for a new authentication if token is expired

## [1.0.08.11] - 2022-11-08

### Added/Changed

- Initial version of ORADAZ
