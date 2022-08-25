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
    authproc = [
        ...
        '60' => [
             'class' => 'attrauthcomanage:COmanageRestClient',
             'apiBaseURL' => 'https://comanage.example.org/registry',
             'username' => 'bob',
             'password' => 'secret',
             'userIdAttribute => 'eduPersonUniqueId',
             'urnNamespace' => 'urn:mace:example.org',
        ],
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
 * Required:
    * `coId`: An integer containing the ID of the CO to use. There is no default value, must not be null.
    * `urnNamespace`: A string to use as the URN namespace of the generated `eduPersonEntitlement` values containing group membership and role information.
    * `voRoles`: An array of default roles to be used for the composition of the entitlements.
    * `urnAuthority`: A string to use as the authority of the generated `eduPersonEntitlement` URN values containing group membership and role information.
    * `registryUrls`: An array of COmanage endpoints representing standard Enrollment Flow types. All the four endpoints are mandatory.
    * `comanage_api_username`: COmanage REST API username.
    * `comanage_api_password`: COmanage REST API password.

 * Optional:
    * `voGroupPrefix`: An array of group prefixes per (CO)mmunity to be used for the composition of the entitlements. Defaults to `urlencode($co_name) . ":group"`.
    * `coUserIdType`: A string that indicates the type of the identifier that the users have. Defaults to `epuid`.
    * `coOrgIdType`: An array containing the Identifier types under the user's Organizational Identities. Defaults to `array('epuid')`.
    * `retrieveAUP`: A boolean value for controlling whether to retrieve Terms & Conditions/Acceptable Use Policy (AUP) information from the COmanage Registry. When `true`, the retrieved AUP information is stored in the state - `$state['rciamAttributes']['aup']`. Defaults to `false`.
    * `userIdAttribute`: A string containing the name of the attribute whose value to use for querying the COmanage Registry. Defaults to `"eduPersonPrincipalName"`.
    * `blacklist`: An array of strings that contains the SPs that the module will skip to process. Defaults to `array()`.
    * `voWhitelist`: An array of strings that contains VOs (COUs) for which the module will generate entitlements. Defaults to `null`. If `null`, the voWhitelist check is skipped.
    * `communityIdps`: An array of strings that contains the Entity Ids of trusted communities. Defaults to `array()`.
    * `communityIdpTags`: An array of strings that contains tags, indicating that every Idp having at least one of them is considered as community. Defaults to `array('community')`.
    * `urnLegacy`: A boolean value for controlling whether to generate `eduPersonEntitlement` URN values using the legacy syntax. Defaults to `false`.
    * `noRoleEntitlements`: A boolean value for controlling whether to generate `eduPersonEntitlement` URN values without role attribute. Defaults to `false`.
    * `certificate`: A boolean value for controlling whether to fetch `Certificates` from User's Profile. Defaults to `false`.
    * `retrieveSshKeys`: A boolean value for controlling whether to retrieve SSH keys from User's Profile. Defaults to `false`.
    * `mergeEntitlements`: A boolean to indicate whether the redundant `eduPersonEntitlement` will be removed from the state. Defaults to `false`.
    * `attrMap`: An array of key,value pairs. These pairs constitute COmanage to SimpleSamlPHP attribute mappings. Currently ONLY Identifier attributes are supported. Defaults to `null`.

Note: In case you need to change the format of the entitlements you need to modify the source code.

### Example authproc filter configuration
```
    authproc = [
        ...
        '60' => [
            'class' => 'attrauthcomanage:COmanageDbClient',
            'coId' => 2,
            'coUserIdType' => 'epuid',            // COmanage terminology
            'coUserIdType' => ['epuid'],     // COmanage terminology
            'userIdAttribute' => 'eduPersonUniqueId',
            'retrieveAUP' => true,
            'blacklist' => [
                'https://www.example.org/sp',
            ],
            'voWhitelist' => [
                'vo.example.org',
            ],
            'communityIdps' => [
               'https://example1.com/idp',
            ],
            'communityIdpTags' => [
               'community',
            ],
            'voRoles' => [
                'member',
                'faculty',
            ],
            'voGroupPrefix' => [
               3 => 'registry',
            ],
            'urnNamespace' => 'urn:mace:example.org',
            'urnAuthority' => 'example.eu',
            'mergeEntitlements' => false,
            'comanage_api_username' => 'rciam',
            'comanage_api_password' => 'password',
            'certificate' => false,
            'retrieveSshKeys' => true,
            'registryUrls' => [
               'self_sign_up'      => 'https://example.com/registry/co_petitions/start/coef:1', // Required
               'sign_up'           => 'https://example.com/registry/co_petitions/start/coef:2', // Required
               'community_sign_up' => 'https://example.com/registry/co_petitions/start/coef:3', // Required
               'registry_login'    => 'https://example.com/registry/co_petitions/auth/login',   // Required
            ],
            // Currently only Indentifier attributes are supported, like
            'attrMap' => [
               'eppn' => 'eduPersonPrincipalName',
               'eptid' => 'eduPersonTargetedID',
               'epuid' => 'eduPersonUniqueId',
               'orcid' => 'eduPersonOrcid',
               'uid' => 'uid',
            ],
        ],
```
### Overriding the default error definitions
At ```templates/exception.tpl.php``` file you can comment out
```
$tag = preg_replace('/attrauthcomanage:/','yourthememodule:', $this->data['e'], 1);
```
replacing ```yourthememodule``` with the name of your theme module. 
Also you must copy the ```attrauthcomanage.definition.json``` file under `yourthememodule/dictionaries` and then change the error messages in order to override the defaults.


## Compatibility matrix

This table matches the module version with the supported SimpleSAMLphp version.

| Module   |  SimpleSAMLphp |
|:--------:|:--------------:|
| v1.x     | v1.14          |
| v2.x     | v1.17+         |


## License
Licensed under the Apache 2.0 license, for details see `LICENSE`.
