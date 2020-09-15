<?php

/**
 * COmanage authproc filter.
 *
 * This class is the authproc filter to get information about the user
 * from the COmanage Registry database.
 *
 * Example configuration in the config/config.php
 *
 *    authproc.aa = array(
 *       ...
 *       '60' => array(
 *            'class' => 'attrauthcomanage:COmanageDbClient',
 *            'coId' => 2,
 *            'userIdAttribute' => 'eduPersonUniqueId',
 *            'voWhitelist' => array(
 *               'vo.example.com',
 *               'vo.example2.com',
 *            ),
 *            'communityIdps' => array(
 *               'https://example1.com/idp',
 *            ),
 *            'voRoles' => array(
 *               'member',
 *               'faculty',
 *            ),
 *            'urnNamespace' => 'urn:mace:example.eu',
 *            'urnAuthority' => 'example.eu',
 *            'mergeEntitlements' => false,
 *            'registryUrls' => array(
 *               'self_sign_up'      => 'https://example.com/registry/co_petitions/start/coef:1',
 *               'sign_up'           => 'https://example.com/registry/co_petitions/start/coef:2',
 *               'community_sign_up' => 'https://example.com/registry/co_petitions/start/coef:3',
 *               'community_sign_up_no_aff' => 'https://example.com/registry/co_petitions/start/coef:4',
 *               'registry_login'    => 'https://example.com/registry/co_petitions/auth/login',
 *            ),
 *       ),
 *
 * @author Nicolas Liampotis <nliam@grnet.gr>
 * @author Nick Evangelou <nikosev@grnet.gr>
 * @author Ioannis Igoumenos <ioigoume@grnet.gr>
 */
class sspmod_attrauthcomanage_Auth_Process_COmanageDbClient extends SimpleSAML_Auth_ProcessingFilter
{
    // List of SP entity IDs that should be excluded from this filter.
    private $blacklist = array();
    // List of allowed types of registry urls
    private $registryUrlTypesAllowed = array(
      'self_sign_up',
      'sign_up',
      'community_sign_up',
      'community_sign_up_no_aff',
      'registry_login');

    private $coId;

    private $coUserIdType = 'epuid';

    private $userIdAttribute = 'eduPersonUniqueId';

    // List of VO names that should be included in entitlements.
    private $voWhitelist = array();

    private $urnNamespace = null;
    private $urnAuthority = null;
    private $registryUrls = array();
    private $communityIdps = array();
    private $mergeEntitlements = false;
    // If true, this filter will also generate entitlements using the
    // legacy URN format
    private $urnLegacy = false;
    private $voRoles = array();
    private $voRolesDef = array();

    private $_basicInfoQuery = 'select'
        . ' person.id,'
        . ' person.status,'
        . ' person.co_id'
        . ' from cm_co_people person'
        . ' inner join cm_co_org_identity_links link'
        . ' on person.id = link.co_person_id'
        . ' inner join cm_org_identities org'
        . ' on link.org_identity_id = org.id'
        . ' inner join cm_identifiers ident'
        . ' on org.id = ident.org_identity_id'
        . ' where'
        . ' person.co_id = :coId'
        . ' and not person.deleted'
        . ' and person.co_person_id is null'
        . ' and not link.deleted'
        . ' and link.co_org_identity_link_id is null'
        . ' and not org.deleted'
        . ' and org.org_identity_id is null'
        . ' and not ident.deleted'
        . ' and ident.identifier_id is null'
        . ' and ident.identifier = :coPersonOrgId';

    private $_loginIdQuery = 'select ident.identifier'
        . ' from cm_identifiers ident'
        . ' where'
        . ' ident.co_person_id = :coPersonId'
        . ' and ident.type = :coPersonIdType'
        . ' and not ident.deleted'
        . ' and ident.identifier_id is null';

    private $profileQuery = 'SELECT'
        . ' name.given,'
        . ' name.family,'
        . ' mail.mail,'
        . ' org.affiliation,'
        . ' org.o,'
        . ' ident.identifier'
        . ' FROM cm_co_people person'
        . ' LEFT OUTER JOIN cm_names name'
        . ' ON person.id = name.co_person_id'
        . ' LEFT OUTER JOIN cm_email_addresses mail'
        . ' ON person.id = mail.co_person_id'
        . ' LEFT OUTER JOIN cm_co_org_identity_links link'
        . ' ON person.id = link.co_person_id'
        . ' LEFT OUTER JOIN cm_org_identities org'
        . ' ON link.org_identity_id = org.id'
        . ' LEFT OUTER JOIN cm_identifiers ident'
        . ' ON person.id = ident.co_person_id'
        . ' WHERE'
        . ' NOT person.deleted'
        . ' AND person.co_person_id IS NULL'
        . ' AND NOT name.deleted'
        . ' AND name.name_id IS NULL'
        . ' AND name.type = \'official\''
        . ' AND NOT mail.deleted'
        . ' AND mail.email_address_id IS NULL'
        . ' AND mail.type = \'official\''
        . ' AND NOT link.deleted'
        . ' AND link.co_org_identity_link_id is null'
        . ' AND NOT org.deleted'
        . ' AND org.org_identity_id is null'
        . ' AND NOT ident.deleted'
        . ' AND ident.type = \'uid\''
        . ' AND ident.identifier_id IS NULL'
        . ' AND person.id = :coPersonId'
        . ' AND name.type = \'official\''
        . ' AND name.primary_name = true'
        . ' AND link.co_org_identity_link_id IS NULL'
        . ' AND NOT org.deleted'
        . ' AND org.org_identity_id is NULL'
        . ' ORDER BY link.org_identity_id ASC LIMIT 1';

    private $certQuery = 'SELECT'
        . ' DISTINCT(cert.subject)'
        . ' FROM cm_co_people AS person'
        . ' INNER JOIN cm_co_org_identity_links AS link'
        . ' ON person.id = link.co_person_id'
        . ' INNER JOIN cm_org_identities AS org'
        . ' ON link.org_identity_id = org.id'
        . ' INNER JOIN cm_certs AS cert'
        . ' ON org.id = cert.org_identity_id'
        . ' WHERE person.id = :coPersonId'
        . ' AND NOT person.deleted'
        . ' AND person.co_person_id IS NULL'
        . ' AND NOT link.deleted'
        . ' AND link.co_org_identity_link_id IS NULL'
        . ' AND org.org_identity_id IS NULL'
        . ' AND NOT org.deleted'
        . ' AND cert.cert_id IS NULL'
        . ' AND NOT cert.deleted';

    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        if (!array_key_exists('coId', $config)) {
            SimpleSAML_Logger::error("[attrauthcomanage] Configuration error: 'coId' not specified");
            throw new SimpleSAML_Error_Exception(
                "attrauthcomanage configuration error: 'coId' not specified");
        }
        if (!is_int($config['coId'])) {
            SimpleSAML_Logger::error("[attrauthcomanage] Configuration error: 'coId' not an integer number");
            throw new SimpleSAML_Error_Exception(
                "attrauthcomanage configuration error: 'coId' not an integer number");
        }
        $this->coId = $config['coId'];

        // urnNamespace config
        if (!array_key_exists('urnNamespace', $config) && !is_string($config['urnNamespace'])) {
          SimpleSAML_Logger::error("[attrauthcomanage] Configuration error: 'urnNamespace' not specified or wrong format(string required)");
          throw new SimpleSAML_Error_Exception(
            "attrauthcomanage configuration error: 'urnNamespace' not specified");
        }
        $this->urnNamespace = $config['urnNamespace'];

        // voRoles config
        if (!array_key_exists('voRoles', $config) && !is_string($config['voRoles'])) {
          SimpleSAML_Logger::error("[attrauthcomanage] Configuration error: 'voRoles' not specified or wrong format(string required)");
          throw new SimpleSAML_Error_Exception(
            "attrauthcomanage configuration error: 'voRoles' not specified");
        }
        $this->voRoles = $config['voRoles'];
        // Get a copy of teh default Roles before enriching with COmanage roles
        $voRolesObject = new ArrayObject($config['voRoles']);
        $this->voRolesDef = $voRolesObject->getArrayCopy();

        // urnAuthority config
        if (!array_key_exists('urnAuthority', $config) && !is_string($config['urnAuthority'])) {
          SimpleSAML_Logger::error("[attrauthcomanage] Configuration error: 'urnAuthority' not specified or wrong format(string required)");
          throw new SimpleSAML_Error_Exception(
            "attrauthcomanage configuration error: 'urnAuthority' not specified");
        }
        $this->urnAuthority = $config['urnAuthority'];

        // Redirect Urls config
        if (!array_key_exists('registryUrls', $config)) {
          SimpleSAML_Logger::error("[attrauthcomanage] Configuration error: 'registryUrls' not specified");
          throw new SimpleSAML_Error_Exception(
            "attrauthcomanage configuration error: 'registryUrls' not specified");
        } else {
          // Check if the keys exist
          $allowed = $this->registryUrlTypesAllowed;
          $invalid_keys = array_filter($config['registryUrls'], function($key) use ($allowed) {
            return !in_array($key, $allowed);
          }, ARRAY_FILTER_USE_KEY);
          $invalid_urls = array_filter($config['registryUrls'], function($value) {
            return !filter_var($value, FILTER_VALIDATE_URL);
          });
          if (!empty($invalid_keys) || !empty($invalid_urls)) {
            SimpleSAML_Logger::error("[attrauthcomanage] Configuration error: 'registryUrls' url or key configuration error");
            throw new SimpleSAML_Error_Exception(
              "attrauthcomanage configuration error: 'registryUrls' url or key configuration error");
          }
        }
        $this->registryUrls = $config['registryUrls'];

        if (array_key_exists('coUserIdType', $config)) {
            if (!is_string($config['coUserIdType'])) {
                SimpleSAML_Logger::error("[attrauthcomanage] Configuration error: 'coUserIdType' not a string literal");
                throw new SimpleSAML_Error_Exception(
                    "attrauthcomanage configuration error: 'coUserIdType' not a string literal");
            }
            $this->coUserIdType = $config['coUserIdType'];
        }

        if (array_key_exists('userIdAttribute', $config)) {
            if (!is_string($config['userIdAttribute'])) {
                SimpleSAML_Logger::error("[attrauthcomanage] Configuration error: 'userIdAttribute' not a string literal");
                throw new SimpleSAML_Error_Exception(
                    "attrauthcomanage configuration error: 'userIdAttribute' not a string literal");
            }
            $this->userIdAttribute = $config['userIdAttribute'];
        }

        if (array_key_exists('blacklist', $config)) {
            if (!is_array($config['blacklist'])) {
                SimpleSAML_Logger::error("[attrauthcomanage] Configuration error: 'blacklist' not an array");
                throw new SimpleSAML_Error_Exception(
                    "attrauthcomanage configuration error: 'blacklist' not an array");
            }
            $this->blacklist = $config['blacklist'];
        }
        if (array_key_exists('voWhitelist', $config)) {
            if (!is_array($config['voWhitelist'])) {
                SimpleSAML_Logger::error("[attrauthcomanage] Configuration error: 'voWhitelist' not an array");
                throw new SimpleSAML_Error_Exception(
                    "attrauthcomanage configuration error: 'voWhitelist' not an array");
            }
            $this->voWhitelist = $config['voWhitelist'];
        }
        if (array_key_exists('communityIdps', $config)) {
            if (!is_array($config['communityIdps'])) {
                SimpleSAML_Logger::error("[attrauthcomanage] Configuration error: 'communityIdps' not an array");
                throw new SimpleSAML_Error_Exception(
                    "attrauthcomanage configuration error: 'communityIdps' not an array");
            }
            $this->communityIdps = $config['communityIdps'];
        }

        if (array_key_exists('urnLegacy', $config)) {
            if (!is_bool($config['urnLegacy'])) {
                SimpleSAML_Logger::error("[attrauthcomanage] Configuration error: 'urnLegacy' not a boolean");
                throw new SimpleSAML_Error_Exception(
                    "attrauthcomanage configuration error: 'urnLegacy' not a boolean");
            }
            $this->urnLegacy = $config['urnLegacy'];
        }
        if (array_key_exists('mergeEntitlements', $config)) {
          if (!is_bool($config['urnLegacy'])) {
            SimpleSAML_Logger::error("[attrauthcomanage] Configuration error: 'mergeEntitlements' not a boolean");
            throw new SimpleSAML_Error_Exception(
              "attrauthcomanage configuration error: 'mergeEntitlements' not a boolean");
          }
          $this->mergeEntitlements = $config['mergeEntitlements'];
        }
    }

    public function process(&$state)
    {
        try {
            assert('is_array($state)');
            if (isset($state['SPMetadata']['entityid']) && in_array($state['SPMetadata']['entityid'], $this->blacklist, true)) {
                SimpleSAML_Logger::debug("[attrauthcomanage] process: Skipping blacklisted SP ". var_export($state['SPMetadata']['entityid'], true));
                return;
            }
            if (empty($state['Attributes'][$this->userIdAttribute])) {
                //echo '<pre>' . var_export($state, true) . '</pre>';
                SimpleSAML_Logger::error("[attrauthcomanage] Configuration error: 'userIdAttribute' not available");
                throw new SimpleSAML_Error_Exception(
                    "attrauthcomanage configuration error: 'userIdAttribute' not available");
            }
            unset($state['Attributes']['uid']);
            $orgId = $state['Attributes'][$this->userIdAttribute][0];
            SimpleSAML_Logger::debug("[attrauthcomanage] process: orgId=" . var_export($orgId, true));
            $basicInfo = $this->_getBasicInfo($orgId);
            SimpleSAML_Logger::debug("[attrauthcomanage] process: basicInfo=". var_export($basicInfo, true));
            if (!empty($basicInfo)) {
                $state['basicInfo'] = $basicInfo;
            }
            if (empty($basicInfo['id']) || empty($basicInfo['status']) || ($basicInfo['status'] !== 'A' && $basicInfo['status'] !== 'GP')) {
                  $state['UserID'] = $orgId;
                  $state['ReturnProc'] = array(get_class($this), 'retrieveCOPersonData');
                  $params = array();
                  $id = SimpleSAML_Auth_State::saveState($state, 'attrauthcomanage:register');
                  $callback = SimpleSAML_Module::getModuleURL('attrauthcomanage/idp_callback.php', array('stateId' => $id));
                  SimpleSAML_Logger::debug("[attrauthcomanage] process: callback url => " . $callback);
                  $params = array("targetnew" => $callback);
                  // Check if community signup is required
                  if (!empty($state['saml:AuthenticatingAuthority']) && in_array(end($state['saml:AuthenticatingAuthority']), $this->communityIdps, true)) {
                      // Redirect to community signup flow with all
                      // attributes available including affiliation
                      if (!empty($state['Attributes']['voPersonExternalAffiliation'])
                          && !empty($state['Attributes']['mail'])
                          && !empty($state['Attributes']['givenName'])
                          && !empty($state['Attributes']['sn'])) {
                          \SimpleSAML\Utils\HTTP::redirectTrustedURL($this->registryUrls['community_sign_up'], $params);
                       }
                       \SimpleSAML\Utils\HTTP::redirectTrustedURL($this->registryUrls['community_sign_up_no_aff'], $params);
                  }
                  $this->_redirect($basicInfo, $state, $params);
            }
            // Get all the data from the COPerson and import them in the state
            $this->retrieveCOPersonData($state);

        } catch (\Exception $e) {
            $this->_showException($e);
        }
    }

    private function _redirect($basicInfo, &$state, $params = array())
    {
        $attributes = $state['Attributes'];
        SimpleSAML_Logger::debug("[attrauthcomanage] _redirect: attributes="
            . var_export($attributes, true));
        // Check Pending Confirmation (PC) / Pending Approval (PA) status
        // TODO: How to deal with 'Expired' accounts?
        if (!empty($basicInfo) && ($basicInfo['status'] === 'PC' || $basicInfo['status'] === 'PA')) {
            \SimpleSAML\Utils\HTTP::redirectTrustedURL($this->registryUrls['registry_login']);
        }
        if (!empty($attributes['eduPersonScopedAffiliation'])
            && !empty($attributes['mail'])
            && !empty($attributes['givenName'])
            && !empty($attributes['sn'])) {
            \SimpleSAML\Utils\HTTP::redirectTrustedURL($this->registryUrls['self_sign_up'], $params);
        }
        \SimpleSAML\Utils\HTTP::redirectTrustedURL($this->registryUrls['sign_up'], $params);
    }

    private function _getBasicInfo($orgId)
    {
        SimpleSAML_Logger::debug("[attrauthcomanage] _getBasicInfo: orgId="
            . var_export($orgId, true));

        $db = SimpleSAML\Database::getInstance();
        $queryParams = array(
            'coId'          => array($this->coId, PDO::PARAM_INT),
            'coPersonOrgId' => array($orgId, PDO::PARAM_STR),
        );
        $stmt = $db->read($this->_basicInfoQuery, $queryParams);
        if ($stmt->execute()) {
            if ($result = $stmt->fetch(PDO::FETCH_ASSOC)) {
                SimpleSAML_Logger::debug("[attrauthcomanage] _getBasicInfo: result="
                    . var_export($result, true));
               return $result;
            }
        } else {
            throw new Exception('Failed to communicate with COmanage Registry: '.var_export($db->getLastError(), true));
        }

        return null;
    }

    private function _getLoginId($personId)
    {
        SimpleSAML_Logger::debug("[attrauthcomanage] _getLoginId: personId="
            . var_export($personId, true));

        $db = SimpleSAML\Database::getInstance();
        $queryParams = array(
            'coPersonId'     => array($personId, PDO::PARAM_INT),
            'coPersonIdType' => array($this->coUserIdType, PDO::PARAM_STR),
        );
        $stmt = $db->read($this->_loginIdQuery, $queryParams);
        if ($stmt->execute()) {
            if ($result = $stmt->fetch(PDO::FETCH_ASSOC)) {
                SimpleSAML_Logger::debug("[attrauthcomanage] _getLoginId: result="
                    . var_export($result, true));
               return $result['identifier'];
            }
        } else {
            throw new Exception('Failed to communicate with COmanage Registry: '.var_export($db->getLastError(), true));
        }

        return null;
    }

    private function getProfile($personId)
    {
        SimpleSAML_Logger::debug("[attrauthcomanage] getProfile: personId="
            . var_export($personId, true));

        $db = SimpleSAML\Database::getInstance();
        $queryParams = array(
            'coPersonId' => array($personId, PDO::PARAM_INT),
        );
        $stmt = $db->read($this->profileQuery, $queryParams);
        if ($stmt->execute()) {
            $result = array();
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            SimpleSAML_Logger::debug("[attrauthcomanage] getProfile: result="
                . var_export($result, true));
            return $result;
        } else {
            throw new Exception('Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true));
        }

        return null;
    }

    private function getCerts($personId)
    {
        SimpleSAML_Logger::debug("[attrauthcomanage] getCerts: personId="
            . var_export($personId, true));

        $result = array();
        $db = SimpleSAML\Database::getInstance();
        $queryParams = array(
            'coPersonId' => array($personId, PDO::PARAM_INT),
        );
        $stmt = $db->read($this->certQuery, $queryParams);
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            SimpleSAML_Logger::debug("[attrauthcomanage] getCerts: result="
                . var_export($result, true));
            return $result;
        } else {
            throw new Exception('Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true));
        }

        return $result;
    }

    /**
     * Get all the memberships and affiliations in the specified CO for the specified user. The COUs while have a cou_id
     * The plain Groups will have cou_id=null
     * @param integer $co_id The CO Id that we will retrieve all memberships for the CO Person
     * @param integer $co_person_id The CO Person that we will retrieve the memberships for
     * @return array Array contents: [group_name, cou_id, affiliation, title, member, owner]
     * @throws Exception
     * @uses SimpleSAML_Logger::debug
     * @uses SimpleSAML\Database::getInstance
     */
    private function getMemberships($co_id, $co_person_id)
    {
        // XXX Since i voWhitelist only the parent VO/COU i can not filter VOs with the query
        $membership_query =
            "SELECT"
            . " DISTINCT substring(groups.name, '^(?:(?:COU?[:])+)?(.+?)(?:[:]mem.+)?$') as group_name,"
            . " string_agg(DISTINCT groups.cou_id::text, ',') as cou_id,"
            . " CASE WHEN groups.name ~ ':admins' THEN null"
            . " ELSE string_agg(DISTINCT nullif(role.affiliation, ''), ',')"
            . " END AS affiliation,"
            . " CASE WHEN groups.name ~ ':admins' THEN null"
            . " ELSE string_agg(DISTINCT nullif(role.title, ''), ',')"
            . " END AS title,"
            . " bool_or(members.member) as member,"
            . " bool_or(members.owner) as owner"
            . " FROM cm_co_groups AS groups"
            . " INNER JOIN cm_co_group_members AS members ON groups.id=members.co_group_id"
            . " AND members.co_group_member_id IS NULL"
            . " AND NOT members.deleted"
            . " AND groups.co_group_id IS NULL"
            . " AND NOT groups.deleted"
            . " AND groups.name not ilike '%members:all'"
            . " AND groups.name not ilike 'CO:admins'"
            . " AND groups.name not ilike 'CO:members:active'"
            . " AND members.co_person_id= :co_person_id"
            . " AND groups.co_id = :co_id"
            . " AND groups.status = 'A'"
            . " LEFT OUTER JOIN cm_cous AS cous ON groups.cou_id = cous.id"
            . " AND NOT cous.deleted"
            . " AND cous.cou_id IS NULL"
            . " LEFT OUTER JOIN cm_co_person_roles AS ROLE ON cous.id = role.cou_id"
            . " AND role.co_person_role_id IS NULL"
            . " AND role.status = 'A'"
            . " AND NOT role.deleted    AND role.co_person_id = members.co_person_id"
            . " GROUP BY"
            . " groups.name";

        $db = SimpleSAML\Database::getInstance();
        // Strip the cou_id from the unnecessary characters
        $queryParams = array(
            'co_id'        => array($co_id, PDO::PARAM_INT),
            'co_person_id' => array($co_person_id, PDO::PARAM_INT),
        );
        $stmt = $db->read($membership_query, $queryParams);
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            SimpleSAML_Logger::debug("[attrauthcomanage] getMemberships: result="
                . var_export($result, true)
            );
            return $result;
        } else {
            throw new Exception('Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true));
        }

        return $result;
    }

    /**
     * Returns nested COU path ready to use in an AARC compatible entitlement
     * @param array $cous
     * @param array $nested_cous_paths
     * @throws RuntimeException Failed to communicate with COmanage database
     * @uses SimpleSAML_Logger::debug
     * @uses SimpleSAML\Database::getInstance
     */
    private function getCouTreeStructure($cous, &$nested_cous_paths)
    {
        $recursive_query =
          "WITH RECURSIVE cous_cte(id, name, parent_id, depth, path) AS ("
          . " SELECT cc.id, cc.name, cc.parent_id, 1::INT AS depth, cc.name::TEXT AS path, cc.id::TEXT AS path_id"
          . " FROM cm_cous AS cc"
          . " WHERE cc.parent_id IS NULL"
          . " UNION ALL"
          . " SELECT c.id, c.name, c.parent_id, p.depth + 1 AS depth,"
          . " (p.path || ':' || c.name::TEXT),"
          . " (p.path_id || ':' || c.id::TEXT)"
          . " FROM cous_cte AS p, cm_cous AS c"
          . " WHERE c.parent_id = p.id"
          . " )"
          . " SELECT * FROM cous_cte AS ccte where ccte.id=:cou_id";

        $db = SimpleSAML\Database::getInstance();
        foreach ($cous as $cou) {
          if (empty($cou['group_name']) || empty($cou['cou_id'])) {
            continue;
          }
          // Strip the cou_id from the unnecessary characters
          $queryParams = array(
            'cou_id' => array($cou['cou_id'], PDO::PARAM_INT),
          );
          $stmt = $db->read($recursive_query, $queryParams);
          if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
              if (strpos($row['path'], ':') !== false) {
                $nested_cous_paths += [
                  $cou['cou_id'] => [
                    'path'           => $row['path'],
                    'path_id_list'   => explode(':', $row['path_id']),
                    'path_full_list' => array_combine(
                      explode(':', $row['path_id']), // keys
                      explode(':', $row['path'])     // values
                    ),
                  ],
                ];
              }
            }
          } else {
            throw new \RuntimeException('Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true));
          }
        }
        SimpleSAML_Logger::debug("[attrauthcomanage] getCouTreeStructure: nested_cous_paths=" . var_export($nested_cous_paths, true));
    }

    /**
     * Add eduPersonEntitlements in the State(no filtering happens here.)
     * @param array $personRoles
     * @param array &$state
     * @param string $vo_name
     * @param string $group_name
     * @param array $memberEntitlements
     * @param integer $cou_id
     * @todo  Old style entitlements to be removed
     */
    private function couEntitlementAssemble($personRoles, &$state, $vo_name, $group_name = "", &$memberEntitlements = null, $cou_id = null)
    {
      foreach ($personRoles as $key => $role) {
        // We need this to filter the cou_id or any other irrelevant information
        if (is_string($key) && $key === 'cou_id') {
          continue;
        }
        if (!empty($role) && is_array($role) && count($role) > 0) {
          $this->couEntitlementAssemble($role, $state, $vo_name, $key, $memberEntitlements, $personRoles['cou_id']);
          continue;
        }
        $group = !empty($group_name) ? ":" . $group_name : "";
        $entitlement =
          $this->urnNamespace                 // URN namespace
          . ":group:"                         // group literal
          . urlencode($vo_name)               // VO
          . $group . ":role=" . $role         // role
          . "#" . $this->urnAuthority;        // AA FQDN
        if (is_array($memberEntitlements)
            && !is_string($key)
            && $role === 'member') {
          if (!empty($personRoles['cou_id'])) { // Under admin this is not defined
            $memberEntitlements += [$personRoles['cou_id'] => $entitlement];
          } else {
            $memberEntitlements['admins'][$cou_id] = $entitlement;
          }
        }
        $state['Attributes']['eduPersonEntitlement'][] = $entitlement;
        // TODO: remove in the near future
        if ($this->urnLegacy) {
            $state['Attributes']['eduPersonEntitlement'][] =
                  $this->urnNamespace          // URN namespace
                  . ':' . $this->urnAuthority  // AA FQDN
                  . $group . ':' . $role       // role
                  . "@"                        // VO delimiter
                  . urlencode($vo_name);       // VO
          } // Depricated syntax
      }
    }

    /**
     * @param array $cou_tree_structure
     * @param array $member_entitlements
     * @param array &$state
     * @param array $orphan_memberships
     */
    private function mergeEntitlements($cou_tree_structure, $member_entitlements, &$state, $orphan_memberships)
    {
      SimpleSAML_Logger::debug("[attrauthcomanage] mergeEntitlements: member_entitlements="
        . var_export($member_entitlements, true));
      SimpleSAML_Logger::debug("[attrauthcomanage] mergeEntitlements: cou_tree_structure="
        . var_export($cou_tree_structure, true));
      SimpleSAML_Logger::debug("[attrauthcomanage] mergeEntitlements: orphan_memberships="
        . var_export($orphan_memberships, true));

      if (empty($member_entitlements) || empty($cou_tree_structure)) {
        return;
      }

      // Retrieve only the entitlements that need handling.
      $filtered_cou_ids = [];
      foreach ($cou_tree_structure as $node) {
          $filtered_cou_ids[] = $node['path_id_list'];
      }
      $filtered_cou_ids = array_values(array_unique(array_merge(...$filtered_cou_ids)));
      SimpleSAML_Logger::debug("[attrauthcomanage] mergeEntitlements: filtered_cou_ids="
        . var_export($filtered_cou_ids, true));

      // XXX Get the COU ids that also have an admin role
      $filtered_admin_cou_ids = !empty($member_entitlements['admins']) ? array_keys($member_entitlements['admins']) : array();
      SimpleSAML_Logger::debug("[attrauthcomanage] mergeEntitlements: filtered_admin_cou_ids="
        . var_export($filtered_admin_cou_ids, true));

      $filtered_entitlements = array_filter(
          $member_entitlements,
          static function ($cou_id) use ($filtered_cou_ids) {
              return in_array(
                  $cou_id,
                  $filtered_cou_ids
              );  // Do not use strict since array_merge returns values as strings
          },
          ARRAY_FILTER_USE_KEY
      );
      SimpleSAML_Logger::debug("[attrauthcomanage] mergeEntitlements: filtered_entitlements="
        . var_export($filtered_entitlements, true));

      // XXX Create the list of all potential groups
      $allowed_cou_ids = array_keys($filtered_entitlements);
      $list_of_candidate_full_nested_groups = [];
      foreach ($cou_tree_structure as $sub_tree) {
          $full_candidate_cou_id = '';
          $full_candidate_entitlement = '';
          foreach ($sub_tree['path_full_list'] as $cou_id => $cou_name) {
              if (in_array($cou_id, $allowed_cou_ids, true)) {
                  $key = array_search($cou_id, $sub_tree['path_id_list']);
                  $cou_name_hierarchy = array_slice($sub_tree['path_full_list'], 0, $key + 1);
                  $cou_name_hierarchy = array_map(
                      function ($cou_name) {
                          return urlencode($cou_name);
                      },
                      $cou_name_hierarchy
                  );
                  $full_candidate_entitlement = implode(':', $cou_name_hierarchy);
                  $cou_id_hierarchy = array_slice($sub_tree['path_id_list'], 0, $key + 1);
                  $full_candidate_cou_id = implode(':', $cou_id_hierarchy);
              }
          }
          if (!empty($full_candidate_cou_id) && !empty($full_candidate_entitlement)) {
              $list_of_candidate_full_nested_groups[$full_candidate_cou_id] = $full_candidate_entitlement;
          }
      }

      SimpleSAML_Logger::debug("[attrauthcomanage] mergeEntitlements: list_of_candidate_full_nested_groups="
        . var_export($list_of_candidate_full_nested_groups, true));

      // XXX Filter the ones that are subgroups from another
      if ($this->mergeEntitlements) {
          $path_id_arr = array_keys($list_of_candidate_full_nested_groups);
          $path_id_cp = array_keys($list_of_candidate_full_nested_groups);
          foreach ($path_id_arr as $path_id_str) {
              foreach ($path_id_cp as $path_id_str_cp) {
                  if (strpos($path_id_str_cp, $path_id_str) !== false
                      && strlen($path_id_str) < strlen($path_id_str_cp)) {
                      unset($path_id_arr[array_search($path_id_str, $path_id_arr)]);
                      continue;
                  }
              }
          }

          $list_of_candidate_full_nested_groups = array_filter(
              $list_of_candidate_full_nested_groups,
              static function ($keys) use ($path_id_arr) {
                  return in_array($keys, $path_id_arr, true);
              },
              ARRAY_FILTER_USE_KEY
          );
      }

      // XXX $vo_nested is already urlencoded here
      foreach ($list_of_candidate_full_nested_groups as $cou_ids => $vo_nested) {
          $entitlement =
              $this->urnNamespace                 // URN namespace
              . ":group:"                         // group literal
              . $vo_nested                        // VO
              . ":role=member"                    // role
              . "#" . $this->urnAuthority;        // AA FQDN

          $state['Attributes']['eduPersonEntitlement'][] = $entitlement;

          // Add the admin roles nested entitlements
          foreach (explode(':', $cou_ids) as $cou_id) {
              if (in_array($cou_id, $filtered_admin_cou_ids)) {
                  $entitlement =
                      $this->urnNamespace                 // URN namespace
                      . ":group:"                         // group literal
                      . $vo_nested                        // VO
                      . ":admins:role=member"             // admin role
                      . "#" . $this->urnAuthority;        // AA FQDN

                  $state['Attributes']['eduPersonEntitlement'][] = $entitlement;
                  break;
              }
          }
      }

      // XXX Add all the parents with the default roles in the state
      foreach ($cou_tree_structure as $sub_tree) {
          // XXX Split the full path and encode each part.
          $parent_vo = array_values($sub_tree['path_full_list'])[0];
          if (!in_array($parent_vo, $this->voWhitelist, true)) {
              continue;
          }
          foreach ($this->voRolesDef as $role) {
              $entitlement =
                  $this->urnNamespace                 // URN namespace
                  . ":group:"                         // group literal
                  . urlencode($parent_vo)             // VO
                  . ":role=" . $role                  // role
                  . "#" . $this->urnAuthority;        // AA FQDN

              $state['Attributes']['eduPersonEntitlement'][] = $entitlement;
          }
      }

      // XXX Add all orphan admins COU groups in the state
      foreach ($orphan_memberships as $membership) {
          SimpleSAML_Logger::debug("[attrauthcomanage] membeship: membeship=" . var_export($membership, true));
          if ($membership['member'] || $membership['owner']) {
              $membership_roles = [];
              if ($membership['member']) {
                  $membership_roles[] = 'member';
              }
              if ($membership['owner']) {
                  $membership_roles[] = 'owner';
              }
              $vo_name = $membership['group_name'];
              if (array_key_exists($membership['cou_id'], $cou_tree_structure)) {
                  $vo_name = $cou_tree_structure[$membership['cou_id']]['path'] . ':admins';
              }
              $vo_name_parts = explode(':', $vo_name);
              $vo_name_parts = array_map(
                  function ($value) {
                      return urlencode($value);
                  },
                  $vo_name_parts
              );
              // XXX Now reconstruct
              foreach ($membership_roles as $role) {
                  $vo_name = implode(':', $vo_name_parts);
                  $entitlement =
                      $this->urnNamespace                 // URN namespace
                      . ":group:"                         // group literal
                      . $vo_name                          // VO
                      . ":role=" . $role                  // role
                      . "#" . $this->urnAuthority;        // AA FQDN
                  $state['Attributes']['eduPersonEntitlement'][] = $entitlement;
              }
          }
      }

      // XXX Remove duplicates
      $state['Attributes']['eduPersonEntitlement'] = array_unique($state['Attributes']['eduPersonEntitlement']);

      // XXX Remove all non root non nested cou entitlements from the $state['Attributes']['eduPersonEntitlement']
      $re = '/(.*):role=member(.*)/m';
      foreach ($filtered_entitlements as $couid => $entitlement) {
          if ($this->isRootCou($couid, $cou_tree_structure)) {
              continue;
          }
          foreach ($this->voRoles as $role) {
              $replacement = '$1:role=' . $role . '$2';
              $replaced_entitlement = preg_replace($re, $replacement, $entitlement);
              $key = array_search($replaced_entitlement, $state['Attributes']['eduPersonEntitlement']);
              if (!is_bool($key)) {
                  unset($replaced_entitlement, $state['Attributes']['eduPersonEntitlement'][$key]);
              }
          }
      }
    }

    /**
     * Extract the Users profile and construct his/her entitlements
     * @param array $state
     * @throws Exception
     */
    private function retrieveCOPersonData(&$state)
    {
        if (isset($state['basicInfo'])) {
            SimpleSAML_Logger::info("[attrauthcomanage] retrieveCOPersonData: " . var_export($state['basicInfo'], true));
            $basicInfo = $state['basicInfo'];
        } else {
            $basicInfo = $this->_getBasicInfo($state['Attributes'][$this->userIdAttribute][0]);
        }
        $loginId = $this->_getLoginId($basicInfo['id']);
        SimpleSAML_Logger::debug("[attrauthcomanage] retrieveCOPersonData: loginId=" . var_export($loginId, true));
        if ($loginId === null) {
            // Normally, this should not happen
            throw new Exception('There is a problem with your EGI account. Please contact support for further assistance.');
        }
        $state['Attributes'][$this->userIdAttribute] = array($loginId);
        $state['UserID'] = $loginId;
        $profile = $this->getProfile($basicInfo['id']);
        if (empty($profile)) {
            return;
        }
        foreach ($profile as $attributes) {
            if (!empty($attributes['given'])) {
                $state['Attributes']['givenName'] = array($attributes['given']);
            }
            if (!empty($attributes['family'])) {
                $state['Attributes']['sn'] = array($attributes['family']);
            }
            if (!empty($attributes['mail'])) {
                $state['Attributes']['mail'] = array($attributes['mail']);
            }
            if (!empty($attributes['affiliation']) && !empty($attributes['o'])) {
                $state['Attributes']['eduPersonScopedAffiliation'] = array(
                    $attributes['affiliation'] . "@" . $attributes['o'],
                );
            }
            if (!empty($attributes['identifier'])) {
                $state['Attributes']['uid'] = array($attributes['identifier']);
            }
        }
        $certs = $this->getCerts($basicInfo['id']);
        foreach ($certs as $cert) {
            if (empty($cert['subject'])) {
                continue;
            }
            if (!array_key_exists('distinguishedName', $state['Attributes'])) {
                $state['Attributes']['distinguishedName'] = array();
            }
            if (!in_array($cert['subject'], $state['Attributes']['distinguishedName'], true)) {
                $state['Attributes']['distinguishedName'][] = $cert['subject'];
            }
        }

        // XXX Get all the memberships from the the CO for the user
        $co_memberships = $this->getMemberships($this->coId, $basicInfo['id']);
        // XXX if this is empty return
        if (empty($co_memberships)) {
            if (!array_key_exists('eduPersonEntitlement', $state['Attributes'])) {
                $state['Attributes']['eduPersonEntitlement'] = array();
            }
            return;
        }
        // XXX Extract the group memberships
        $group_memberships = array_filter(
            $co_memberships,
            static function ($value) {
                if (is_null($value['cou_id'])) {
                    return $value;
                }
            }
        );
        SimpleSAML_Logger::debug("[attrauthcomanage] group_memberships=" . var_export($group_memberships, true));

        // XXX Extract the cou memberships
        // TODO: Make some more clearance here. Remove also thn VOs that should have an entitlement. Be carefull about multi tenacy
        // TODO: This needs the voWhitelist which should be a configuration per CO
        // XXX This will make things simpler and faster below
        $co_memberships = array_filter(
            $co_memberships,
            static function ($value) {
                if (!is_null($value['cou_id'])) {
                    return $value;
                }
            }
        );
        SimpleSAML_Logger::debug("[attrauthcomanage] co_memberships=" . var_export($co_memberships, true));


        // XXX Construct the plain group Entitlements
        $this->groupEntitlemeAssemble($state, $group_memberships, $coId, $voPrefix);

        // XXX Get the Nested COUs for the user
        $nested_cous = [];
        $this->getCouTreeStructure($co_memberships, $nested_cous);

        // Define the array that will hold the member entitlements
        $members_entitlements = [];
        // Iterate over the COUs and construct the entitlements
        foreach ($co_memberships as $idx => $cou) {
            if (empty($cou['group_name'])) {
                continue;
            }
            $vo_roles = array();
            if (!in_array($cou['group_name'], $this->voWhitelist, true)) {
                // XXX Check if there is a root COU that is in the voWhitelist
                // XXX :admins this is not part of the voWhiteList that's why i do not get forward
                $parent_cou_name = $this->getCouRootParent($cou['group_name'], $nested_cous);
                if (!in_array($parent_cou_name, $this->voWhitelist, true)
                    && strpos($cou['group_name'], ':admins') === false) {
                    // XXX Remove a child COU that has no parent in the voWhitelist OR
                    // XXX Remove if it does not represent an admins group AND
                    unset($co_memberships[$idx]);
                    continue;
                }
                if (!in_array($parent_cou_name, $this->voWhitelist, true)
                    && !strpos($cou['group_name'], ':admins') === false) {
                    continue;
                }
            }
            if (!array_key_exists('eduPersonEntitlement', $state['Attributes'])) {
                $state['Attributes']['eduPersonEntitlement'] = array();
            }

            $voName = $cou['group_name'];
            SimpleSAML_Logger::debug("[attrauthcomanage] voName=" . var_export($voName, true));

            // Assemble the roles
            // If there is nothing to assemble then keep the default ones
            // TODO: Move this to function
            $cou['title'] = !empty($cou['title']) ? $cou['title'] : "";
            $cou['affiliation'] = !empty($cou['affiliation']) ? $cou['affiliation'] : "";
            // Explode both
            $cou_titles = explode(',', $cou['title']);
            $cou_affiliations = explode(',', $cou['affiliation']);

            // XXX Translate the ownership and membership of the group to a role
            if (filter_var($cou['owner'], FILTER_VALIDATE_BOOLEAN)) {
                $vo_roles[] = 'owner';
            }
            if (filter_var($cou['member'], FILTER_VALIDATE_BOOLEAN)) {
                $vo_roles[] = 'member';
            }
            $vo_roles = array_unique(array_merge($cou_titles, $cou_affiliations, $vo_roles));
            $vo_roles = array_filter(
                $vo_roles,
                static function ($value) {
                    return !empty($value);
                }
            );
            // Lowercase all roles
            $vo_roles = array_map('strtolower', $vo_roles);
            // Merge the default roles with the ones constructed from the COUs
            $vo_roles = array_unique(array_merge($vo_roles, $this->voRoles));
            // Get the admins group if exists
            $cou_admins_group = array_values(
                array_filter(
                    $co_memberships,
                    static function ($value) use ($voName) {
                        if ($value['group_name'] === ($voName . ':admins')) {
                            return $value;
                        }
                    }
                )
            );

            SimpleSAML_Logger::debug("[attrauthcomanage] cou_admins_group=" . var_export($cou_admins_group, true));
            // Handle as a role the membership and ownership of admins group
            if (!empty($cou_admins_group[0]['member']) && filter_var($cou_admins_group[0]['member'], FILTER_VALIDATE_BOOLEAN)) {
                $vo_roles['admins'][] = 'member';
            }
            if (!empty($cou_admins_group[0]['owner']) && filter_var($cou_admins_group[0]['owner'], FILTER_VALIDATE_BOOLEAN)) {
                $vo_roles['admins'][] = 'owner';
            }

            // XXX This is needed in mergeEntitlements function
            $vo_roles['cou_id'] = $cou['cou_id'];
            // todo: Move upper to voRoles Create function

            SimpleSAML_Logger::debug("[attrauthcomanage] retrieveCOPersonData voRoles[{$voName}]=". var_export($vo_roles, true));
            $this->couEntitlementAssemble($vo_roles, $state, $voName, "", $members_entitlements);
            // XXX Remove the ones already done
            unset($co_memberships[$idx]);
        } // foreach cou

        // Fix nested COUs entitlements
        $this->mergeEntitlements($nested_cous, $members_entitlements, $state, $co_memberships);

        if (!empty($state['Attributes']['eduPersonEntitlement'])) {
            SimpleSAML_Logger::debug("[attrauthcomanage] retrieveCOPersonData AFTER: eduPersonEntitlement=" . var_export($state['Attributes']['eduPersonEntitlement'], true));
        }
    }

    /**
     * Construct the plain group entitlements. No nesting supported.
     * @param array $state
     * @param array $memberships_groups
     * @param integer $co_id
     * @param string $voPrefix
     * @todo Replace voPrefix with a configuration variable
     * @todo Replace $co_id with a configuration variable
     */
    private function groupEntitlemeAssemble(&$state, $memberships_groups, $co_id, $voPrefix)
    {
        if (empty($memberships_groups)) {
            return;
        }
        foreach ($memberships_groups as $group) {
            $roles = array();
            if ($group['member'] === true) {
                $roles[] = "member";
            }
            if ($group['owner'] === true) {
                $roles[] = "owner";
            }
            if (!array_key_exists('eduPersonEntitlement', $state['Attributes'])) {
                $state['Attributes']['eduPersonEntitlement'] = array();
            }
            // todo: Move this to configuration
            $groupPrefix = ($co_id === 5) ? $voPrefix . 'group:': $voPrefix . 'registry:';
            foreach ($roles as $role) {
                $state['Attributes']['eduPersonEntitlement'][] =
                    $this->urnNamespace          // URN namespace
                    . ":group:registry:"         // URN namespace
                    . urlencode($group['group_name'])      // VO
                    . ":role=" . $role             // role
                    . "#" . $this->urnAuthority; // AA FQDN
                // Enable legacy URN syntax for compatibility reasons?
                if ($this->urnLegacy) {
                    $state['Attributes']['eduPersonEntitlement'][] =
                        $this->urnNamespace          // URN namespace
                        . ':' . $this->urnAuthority  // AA FQDN
                        . ':' . $role                // role
                        . "@"                        // VO delimiter
                        . urlencode($group['group_name']);     // VO
                }
            }
        }
    }

    /**
     * @param string $cou_name the name of the COU
     * @param array $cou_nested Array containing the tree structure of the relevant COUs as composed in getCouTreeStructure
     * @return string cou_name or empty string
     */
    private function getCouRootParent($cou_name, $cou_nested)
    {
      foreach ($cou_nested as $hierarchy) {
        if (!in_array($cou_name, $hierarchy['path_full_list'])) {
          continue;
        }
        return array_values($hierarchy['path_full_list'])[0];
      }
      return '';
    }

    /**
     * @param integer $couid
     * @param array $cou_nested
     * @return bool
     */
    private function isRootCou($couid, $cou_nested)
    {
      foreach ($cou_nested as $hierarchy) {
        $root_key = array_keys($hierarchy['path_full_list'])[0];
        if ($root_key == $couid) {
          return true;
        }
      }
      return false;
    }

    private function _showException($e)
    {
        $globalConfig = SimpleSAML_Configuration::getInstance();
        $t = new SimpleSAML_XHTML_Template($globalConfig, 'attrauthcomanage:exception.tpl.php');
        $t->data['e'] = $e->getMessage();
        $t->show();
        exit();
    }
}
