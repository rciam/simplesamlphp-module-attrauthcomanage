# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.0.0]
This version is compatible with SimpleSAMLphp v1.14

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
