# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.1.1] - 2019-01-22

### Fixed
- Fix typos in coid var reference and legacy URN formatting

## [v1.1.0] - 2019-01-21

This version is compatible with [SimpleSAMLphp v1.14](https://simplesamlphp.org/docs/1.14/simplesamlphp-changelog)

### Added
- COmanageDbClient class
  - Get the following information about the user:
    - user's profile (given name, family name, organisation, affiliation, identifier)
    - certificate (subject DN)
    - role attributes (COU membership)
    - group membership (group member role)
  - Create eduPersonEntilement values based on:
    - roles attributes (COU membership)
    - groups (group member role)
  - Store the session into `target_new` query parameter. Use the stored seesion for the purpose of redirecting the user to the SP at the end of Registry enrollment.

### Changed
- Moved placeholder variables to configuration
  - urnNamespace
  - urnAuthority
  - COmanage registry redirect URLs
  - voRoles

### Fixed
- sql query failure due to typo error
