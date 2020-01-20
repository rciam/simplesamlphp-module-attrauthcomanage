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
 *            'urnNamespace' => 'urn:mace:example.eu',
 *            'urnAuthority'         => 'example.eu',
 *            'registryUrls' => array(
 *               'self_sign_up'      => 'https://example.com/registry/co_petitions/start/coef:1',
 *               'sign_up'           => 'https://example.com/registry/co_petitions/start/coef:2',
 *               'community_sign_up' => 'https://example.com/registry/co_petitions/start/coef:3',
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

    private $couQuery = 'SELECT'
        . ' DISTINCT (cou.name)'
        . ' FROM cm_cous AS cou'
        . ' INNER JOIN cm_co_person_roles AS role'
        . ' ON cou.id = role.cou_id'
        . ' WHERE'
        . ' role.co_person_id = :coPersonId'
        . ' AND NOT cou.deleted'
        . ' AND cou.cou_id IS NULL'
        . ' AND role.co_person_role_id IS NULL'
        . ' AND role.affiliation = \'member\''
        . ' AND role.status = \'A\''
        . ' AND NOT role.deleted'
        . ' ORDER BY'
        . ' cou.name DESC';

    private $groupQuery = 'SELECT'
        . ' DISTINCT (gr.name),'
        . ' gm.member,'
        . ' gm.owner'
        . ' FROM cm_co_groups AS gr'
        . ' INNER JOIN cm_co_group_members AS gm'
        . ' ON gr.id=gm.co_group_id'
        . ' WHERE'
        . ' gm.co_person_id= :coPersonId'
        . ' AND gm.co_group_member_id IS NULL'
        . ' AND NOT gm.deleted'
        . ' AND gr.co_group_id IS NULL'
        . ' AND NOT gr.deleted'
        . ' AND gr.co_id = :coId'
        . ' AND gr.group_type = \'S\''
        . ' AND gr.status = \'A\''
        . ' ORDER BY'
        . ' gr.name DESC';

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
        $this->_coId = $config['coId']; 

        // urnNamespace config
        if (!array_key_exists('urnNamespace', $config) && !is_string($config['urnNamespace'])) {
          SimpleSAML_Logger::error("[attrauthcomanage] Configuration error: 'urnNamespace' not specified or wrong format(string required)");
          throw new SimpleSAML_Error_Exception(
            "attrauthcomanage configuration error: 'urnNamespace' not specified");
        }
        $this->urnNamespace = $config['urnNamespace'];

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
            SimpleSAML_Logger::debug("[attrauthcomanage] process: orgId=". var_export($orgId, true));
            $basicInfo = $this->_getBasicInfo($orgId);
            SimpleSAML_Logger::debug("[attrauthcomanage] process: basicInfo=". var_export($basicInfo, true));
            if (empty($basicInfo['id']) || empty($basicInfo['status']) 
                || ($basicInfo['status'] !== 'A' && $basicInfo['status'] !== 'GP')) {
                  $state['UserID'] = $orgId;
                  $params = array();
                  $id = SimpleSAML_Auth_State::saveState($state, 'attrauthcomanage:register');
                  $callback = SimpleSAML_Module::getModuleURL('attrauthcomanage/idp_callback.php', array('stateId' => $id));
                  SimpleSAML_Logger::debug("[attrauthcomanage] process: callback url => " . $callback);
                  $params = array("targetnew" => $callback);
                  if (!empty($state['saml:AuthenticatingAuthority']) && in_array(end($state['saml:AuthenticatingAuthority']), $this->communityIdps, true)) {
                    \SimpleSAML\Utils\HTTP::redirectTrustedURL($this->registryUrls['community_sign_up'], $params);
                  }
                  $this->_redirect($basicInfo, $state, $params);
            }
            $loginId = $this->_getLoginId($basicInfo['id']);
            SimpleSAML_Logger::debug("[attrauthcomanage] process: loginId=". var_export($loginId, true));
            if ($loginId === null) {
                // Normally, this should not happen
                throw new Exception('There is a problem with your account. Please contact support for further assistance.');
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
                        $attributes['affiliation'] . "@" . $attributes['o']
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
            $cous = $this->getCOUs($basicInfo['id']);
            foreach ($cous as $cou) {
                if (empty($cou['name'])) {
                    continue;
                }
                if (!in_array($cou['name'], $this->voWhitelist, true)) {
                    continue;
                }
                $voName = $cou['name'];
                // TODO: make roles configurable
                $roles = array("member", "vm_operator");
                if (!array_key_exists('eduPersonEntitlement', $state['Attributes'])) {
                    $state['Attributes']['eduPersonEntitlement'] = array();
                }
                foreach ($roles as $role) {
                    $state['Attributes']['eduPersonEntitlement'][] =
                        $this->urnNamespace          // URN namespace
                        . ":group:"                  // group literal
                        . urlencode($voName)         // VO
                        . ":role=".$role             // role
                        . "#" . $this->urnAuthority; // AA FQDN
                }
            }

            $groups = $this->getGroups($basicInfo['id'], $this->coId);
            foreach ($groups as $group) {
                $groupName = $group['name'];
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
                foreach ($roles as $role) {
                    $state['Attributes']['eduPersonEntitlement'][] =
                        $this->urnNamespace          // URN namespace
                        . ":group:registry:"         // URN namespace
                        . urlencode($groupName)      // VO
                        . ":role=".$role             // role
                        . "#" . $this->urnAuthority; // AA FQDN
                }
            }
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
        \SimpleSAML\Utils\HTTP::redirectTrustedURL($this->registryUrls['sign_up'], $params);
    }

    private function _getBasicInfo($orgId)
    {
        SimpleSAML_Logger::debug("[attrauthcomanage] _getBasicInfo: orgId="
            . var_export($orgId, true));

        $db = SimpleSAML\Database::getInstance();
        $queryParams = array(
            'coId' => array($this->coId, PDO::PARAM_INT),
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
            'coPersonId' => array($personId, PDO::PARAM_INT),
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
            throw new Exception('Failed to communicate with COmanage Registry: '.var_export($db->getLastError(), true));
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
            throw new Exception('Failed to communicate with COmanage Registry: '.var_export($db->getLastError(), true));
        }

        return $result;
    }

    private function getCOUs($personId)
    {
        SimpleSAML_Logger::debug("[attrauthcomanage] getCOUs: personId="
            . var_export($personId, true));

        $result = array();
        $db = SimpleSAML\Database::getInstance();
        $queryParams = array(
            'coPersonId' => array($personId, PDO::PARAM_INT),
        );
        $stmt = $db->read($this->couQuery, $queryParams);
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            SimpleSAML_Logger::debug("[attrauthcomanage] getCOUs: result="
                . var_export($result, true));
            return $result;
        } else {
            throw new Exception('Failed to communicate with COmanage Registry: '.var_export($db->getLastError(), true));
        }

        return $result;
    }

    private function getGroups($personId, $coId)
    {
        SimpleSAML_Logger::debug("[attrauthcomanage] getGroups: personId="
            . var_export($personId, true));
        SimpleSAML_Logger::debug("[attrauthcomanage] getGroups: coId="
          . var_export($coId, true));

        $result = array();
        $db = SimpleSAML\Database::getInstance();
        $queryParams = array(
            'coPersonId' => array($personId, PDO::PARAM_INT),
            'coId' => array($coId, PDO::PARAM_INT),
        );
        $stmt = $db->read($this->groupQuery, $queryParams);
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            SimpleSAML_Logger::debug("[attrauthcomanage] getGroups: result="
                . var_export($result, true));
            return $result;
        } else {
            throw new Exception('Failed to communicate with COmanage Registry: '.var_export($db->getLastError(), true));
        }

        return $result;
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
