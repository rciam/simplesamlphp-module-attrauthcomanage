# simplesamlphp-module-attrauthcomanage
A SimpleSAMLphp module for retrieving attributes from [COmanage Registry](https://spaces.internet2.edu/display/COmanage/Home) and adding them to the list of attributes received from the identity provider. 

In a nuthshell, this module provides a set of SimpleSAMLphp authentication processing filters allowing to use COmanage Registry as an Attribute Authority. Specifically, the module supports retrieving the following user information from COmanage:
  * CO person profile information, including login identifiers
  * CO group membership information, which is encapsulated in `eduPersonEntitlement` attribute values

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

## License
Licensed under the Apache 2.0 license, for details see `LICENSE`.
