# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.5.7] - 2021-03-29

### Added

- Support for redirecting user to community signup flow without affiliation information

## [v1.5.6] - 2021-01-15

### Fixed

- Fix agreed aup revision with null value evalueated falsely
- Minor code style changes

## [v1.5.5] - 2021-01-14

### Fixed

- Bug where retrieval of AUP information was skipped when the user had no COU or Group membership

## [v1.5.4] - 2021-01-13

### Added
- User's Terms and Conditions/Acceptable Use Policy (AUP) information in state information
- User's COPerson ID in state information
- Support for retrieving user's SSH keys

## [v1.5.3] - 2020-12-04

### Added
- Dictionary for error messages

## [v1.5.2] - 2020-11-26

### Changed
- Improve handling of suspended users

## [v1.5.1] - 2020-11-25

### Added
- `coOrgIdType` configuration option. List of Identifier types associated with user's Organizational Identities

### Changed
- Calculation of user's Profile Identifier. A valid Identifier must be an authenticator and must not be expired


## [v1.5.0] - 2020-11-17
🌹

### Added

- `attrMap` configuration option. Map COmanage Registry `IdentifierEnum` class values to SimpleSAMLphp attibute names

## Changed

- Improve calculation of COPerson's profile attributes

## [v1.4.2] - 2020-11-11

### Added

- Add option to skip `voWhitelist` checks, if `voWhitelist` is `null`

## [v1.4.1] - 2020-11-04

### Added

- Add configuration for enabling the retrieval of certificate information

## [v1.4.0] - 2020-10-09

### Added

- Support for querying terms & conditions agreement information

## [v1.3.5] - 2020-10-09

### Fixed

- Fixed bug allowing duplicate `eduPersonScopedAffiliation` attribute values

## [v1.3.4] - 2020-09-28

### Added

- Added `voPersonVerifiedEmail` attribute 

### Changed

- Refactored `getProfile` query

## [v1.3.3] - 2020-09-24

### Added

- Added `voGroupPrefix` configuration option to support multitenacy

### Fixed

- Fixed faulty condition in entitlement construction
- Fixed uninitialized variables
- Exclude parent COU default roles if the user is only a member of the `admins` group and has no affiliation with the COU
- Minor code improvements

## [v1.3.2] - 2020-09-15

### Fixed

- Fix wrong calculation of entitlements if the user is an admin but has no affiliation in a COU

### Changed

- Fetch COPerson memberships in one query

## [v1.3.1] - 2020-09-08

### Fixed

- Fixed bug when encoding COUs not in voWhitelist

## [v1.3.0] - 2020-09-08

### Added

- Encode nested COUs in entitlements according to [AARC-G002](https://aarc-community.org/guidelines/aarc-g002)

## [v1.2.2] - 2020-02-23

### Fixed

- Fixes target\_new URL redirect for self sign-up flow
- Fixes evaluation of member and owner roles of COU admins group

## [v1.2.1] - 2020-02-14

### Fixed

- Fetch missing CO Person data when resuming state from target\_new URL

## [v1.2.0] - 2020-02-12

### Added

- Encode COU role title and affiliation as role information in generated entitlements
- Encode COU admins group member and owner role information in generated entitlements

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
