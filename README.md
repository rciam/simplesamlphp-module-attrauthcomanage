# simplesamlphp-module-attrauthcomanage
A SimpleSAMLphp module for retrieving attributes from [COmanage Registry](https://spaces.internet2.edu/display/COmanage/Home) and adding them to the list of attributes received from the identity provider.

In a nuthshell, this module provides a set of SimpleSAMLphp authentication processing filters allowing to use COmanage Registry as an Attribute Authority. Specifically, the module supports retrieving the following user information from COmanage:
  * CO person profile information, including login identifiers
  * CO group membership information, which is encapsulated in `eduPersonEntitlement` attribute values following the [AARC-G002](https://aarc-community.org/guidelines/aarc-g002/) specification

To this end, the above information can be retrieved through the COmanage Registry REST API. Support for directly querying the COmanage Registry DB is also foreseen.

## COmanage REST API client
The `attrauthcomanage:COmanageRestClient` authentication processing filter is implemented as a COmanage Registry REST API client. As such, it needs to authenticate via a simple user/password pair transmitted over HTTPS as part of a basic auth flow. For details, see https://spaces.internet2.edu/display/COmanage/REST+API

### COmanage configuration
COmanage Platform Administrators can add and manage API Users via `Platform >> API Users`.

### SimpleSAMLphp configuration
The following authproc filter configuration options are supported:
  * `apiBaseURL`: A string to use as the base URL of the COmanage Registry REST API. There is no default value.
  * `username`: A string to use as the username of the COmanage Registry API user. There is no default value.
  * `password`: A string to use as the password of the COmanage Registry API user. There is no default value.
  * `userIdAttribute`: A string containing the name of the attribute whose value to use for querying the COmanage Registry. Defaults to `"eduPersonPrincipalName"`.
  * `verifyPeer`: A boolean to indicate whether to verify the SSL certificate of the HTTPS server providing access to the COmanage Registry REST API. Defaults to `true`.
  * `urnNamespace`: A string to use as the URN namespace of the generated `eduPersonEntitlement` values containing CO group membership information. Defauls to `"urn:mace:example.org"`.

### Example authproc filter configuration
```
    authproc = array(
        ...
        '60' => array(
             'class' => 'attrauthcomanage:COmanageRestClient',
             'apiBaseURL' => 'https://comanage.example.org/registry',
             'username' => 'bob',
             'password' => 'secret',
             'userIdAttribute => 'eduPersonUniqueId',
             'urnNamespace' => 'urn:mace:example.org',
        ),
```

## COmanage Database client
The `attrauthcomanage:COmanageDbClient` authentication processing filter is implemented as a SQL client. This module uses the SimpleSAML\Database library to connect to the database. To configure the database connection edit the following attributes in the `config.php`:

```
    /*
     * Database connection string.
     * Ensure that you have the required PDO database driver installed
     * for your connection string.
     */
    'database.dsn' => 'mysql:host=localhost;dbname=saml',
    /*
     * SQL database credentials
     */
    'database.username' => 'simplesamlphp',
    'database.password' => 'secret',
```

Optionally, you can configure a database slave by editing the `database.slaves` attribute.

### SimpleSAMLphp configuration
The following authproc filter configuration options are supported:
  * `coId`: Required, an integer containing the ID of the CO to use. There is no default value, must not be null.
  * `coUserIdType`: Optional, a string that indicates the type of the identifier that the users have. Defaults to `epuid`.
  * `userIdAttribute`: Optional, a string containing the name of the attribute whose value to use for querying the COmanage Registry. Defaults to `"eduPersonPrincipalName"`.
  * `blacklist`: Optional, an array of strings that contains the SPs that the module will skip to process.
  * `voWhitelist`: Optional, an array of strings that contains VOs (COUs) for which the module will generate entitlements.
  * `communityIdps`: Optional, an array of strings that contains the Entity Ids of trusted communities.
  * `urnNamespace`: Required, a string to use as the URN namespace of the generated `eduPersonEntitlement` values containing group membership and role information.
  * `voRoles`: Required, an array of default roles to be used for the composition of the entitlements.
  * `urnAuthority`: Required, a string to use as the authority of the generated `eduPersonEntitlement` URN values containing group membership and role information.
  * `registryUrls`: Required, an array of COmanage endpoints representing standard Enrollment Flow types. All the four endpoints are mandatory.
  * `urnLegacy`: Optional, a boolean value for controlling whether to generate `eduPersonEntitlement` URN values using the legacy syntax. Defaults to `false`.
  
Note: In case you need to change the format of the entitlements you need to modify the source code.

### Example authproc filter configuration
```
    authproc = array(
        ...
        '60' => array(
            'class' => 'attrauthcomanage:COmanageDbClient',
            'coId' => 2,
            'coUserIdType' => 'epuid',
            'userIdAttribute' => 'eduPersonUniqueId',
            'blacklist' => array(
                'https://www.example.org/sp',
            ),
            'voWhitelist' => array(
                'vo.example.org',
            ),
            'communityIdps' => array(
               'https://example1.com/idp',
            ),
            'voRoles' => array(
                'member',
                'faculty',
            ),
            'urnNamespace' => 'urn:mace:example.org',
            'urnAuthority' => 'example.eu',
            'registryUrls' => array(
               'self_sign_up'      => 'https://example.com/registry/co_petitions/start/coef:1', // Required
               'sign_up'           => 'https://example.com/registry/co_petitions/start/coef:2', // Required
               'community_sign_up' => 'https://example.com/registry/co_petitions/start/coef:3', // Required
               'registry_login'    => 'https://example.com/registry/co_petitions/auth/login',   // Required
            ),
        ),
```

## Compatibility matrix

This table matches the module version with the supported SimpleSAMLphp version.

| Module |  SimpleSAMLphp |
|:------:|:--------------:|
| v1.0   | v1.14          |
| v1.1   | v1.14          |
| v1.2   | v1.14          |
| v2.0   | v1.17          |

## License
Licensed under the Apache 2.0 license, for details see `LICENSE`.
