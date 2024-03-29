<?php

/**
 * COmanage authproc filter.
 *
 * This class is the authproc filter to get information about the user
 * from the COmanage Registry database.
 *
 * Example configuration in the config/config.php
 *
 *    authproc.aa = [
 *       ...
 *       '60' => [
 *            'class' => 'attrauthcomanage:COmanageDbClient',
 *            'coId' => 2,
 *            'coTermsId' => 1,
 *            'coOrgIdType' => ['epuid'],
 *            'coUserIdType' => 'epuid',
 *            'userIdAttribute' => 'eduPersonPrincipalName',
 *            'certificateDnAttribute' => 'voPersonCertificateDN',
 *            'voWhitelist' => [
 *               'vo.example.com',
 *               'vo.example2.com',
 *            ],
 *            'communityIdps' => [
 *               'https://example1.com/idp',
 *            ],
 *            'communityIdpTags' => [
 *                'community',
 *            ],
 *            'voRoles' => [
 *               'member',
 *               'faculty',
 *            ],
 *            'voGroupPrefix' => [
 *               3 => 'registry',
 *            ],
 *            'urnNamespace' => 'urn:mace:example.eu',
 *            'urnAuthority' => 'example.eu',
 *            'retrieveAUP' => true,
 *            'mergeEntitlements' => false,
 *            'noRoleEntitlements' => false,
 *            'certificate' => false,
 *            'retrieveSshKeys' => true,
 *            'registryUrls' => [
 *               'self_sign_up'             => 'https://example.com/registry/co_petitions/start/coef:1',
 *               'sign_up'                  => 'https://example.com/registry/co_petitions/start/coef:2',
 *               'community_sign_up'        => 'https://example.com/registry/co_petitions/start/coef:3',
 *               'community_sign_up_no_aff' => 'https://example.com/registry/co_petitions/start/coef:4',
 *               'registry_login'           => 'https://example.com/registry/co_petitions/auth/login',
 *            ],
 *            // Currently only Indentifier attributes are supported, like
 *            'attrMap' => [
 *               'eppn' => 'eduPersonPrincipalName',
 *               'eptid' => 'eduPersonTargetedID',
 *               'epuid' => 'eduPersonUniqueId',
 *               'orcid' => 'eduPersonOrcid',
 *               'uid' => 'uid',
 *            ],
 *       ],
 *
 * @author Nicolas Liampotis <nliam@grnet.gr>
 * @author Nick Evangelou <nikosev@grnet.gr>
 * @author Ioannis Igoumenos <ioigoume@grnet.gr>
 * @author Nick Mastoris <nmastoris@grnet.gr>
 */
namespace SimpleSAML\Module\attrauthcomanage\Auth\Process;

use PDO;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\XHTML\Template;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Database;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module\attrauthcomanage\Attributes;
use SimpleSAML\Module\attrauthcomanage\Enrollment;
use SimpleSAML\Module\attrauthcomanage\User;
use SimpleSAML\Module\attrauthcomanage\Enums\StatusEnum as StatusEnum;
use SimpleSAML\Module\attrauthcomanage\Enums\EndpointCmgEnum as EndpointCmgEnum;
use SimpleSAML\Module\attrauthcomanage\Enums\OrgIdentityStatusEnum as OrgIdentityStatusEnum;

class COmanageDbClient extends \SimpleSAML\Auth\ProcessingFilter
{
    // List of SP entity IDs that should be excluded from this filter.
    private $blacklist = [];

    private $coId;
    private $coUserIdType = 'epuid';
    private $coOrgIdType = ['epuid'];

    private $userIdAttribute = 'eduPersonPrincipalName';
    private $certificateDnAttribute = 'voPersonCertificateDN';

    // List of VO names that should be included in entitlements.
    private $voWhitelist = null;
    private $attrMap = null;

    private $urnNamespace = null;
    private $urnAuthority = null;
    private $certificate = false;
    private $retrieveSshKeys = false;
    private $retrieveAUP = false;
    private $registryUrls = [];
    private $communityIdps = [];
    private $communityIdpTags = ['community'];
    private $mergeEntitlements = false;
    private $voGroupPrefix = [];
    // If true, this filter will also generate entitlements using the
    // legacy URN format
    private $urnLegacy = false;
    // If true, this filter will also generate entitlements without the role attribute
    private $noRoleEntitlements = false;
    private $voRoles = [];
    private $voRolesDef = [];
    private $voRolesInter = [];
    private $coGroupMemberships = [];
    private $comanage_api_username = null;
    private $comanage_api_password = null;
    private $orgIdentity = null;
    private $basicInfoQuery = 'select'
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

    private $coPersonIdentQuery = 'select ident.identifier'
        . ' from cm_identifiers ident'
        . ' where'
        . ' ident.co_person_id = :coPersonId'
        . ' and ident.type = :coPersonIdType'
        . ' and not ident.deleted'
        . ' and ident.identifier_id is null';

    // If the OrgIdentity is of status Removed we will not construct the organization attribute
    private $profileQuery = "SELECT string_agg(DISTINCT name.given, ',') AS given,"
        . " string_agg(DISTINCT name.family, ',') AS family,"
        . " string_agg(DISTINCT mail.id::text || ':' || mail.mail || ':' || mail.verified::text, ',')   AS mail,"
        . " string_agg(DISTINCT ident.type || ':' || ident.identifier, ',') AS identifier,"
        . " (select string_agg(coi.affiliation || '@' || coi.o, ',') as eduPersonScopedAffiliation"
        . " from cm_org_identities as coi"
        . " inner join cm_co_org_identity_links ccoil on coi.id = ccoil.org_identity_id and"
        . " not coi.deleted and not ccoil.deleted and"
        . " coi.o is not null and coi.o != '' and"
        . " coi.status != '" . OrgIdentityStatusEnum::Removed . "' and"
        . " coi.affiliation is not null and coi.affiliation != ''"
        . " where ccoil.co_person_id = :coPersonId),"
        . " (select string_agg(coi.o, ',') as organization"
        . " from cm_org_identities as coi"
        . " inner join cm_co_org_identity_links ccoil on coi.id = ccoil.org_identity_id and"
        . " not coi.deleted and not ccoil.deleted and"
        . " coi.o is not null and coi.o != '' and coi.status != '" . OrgIdentityStatusEnum::Removed . "'"
        . " where ccoil.co_person_id = :coPersonId)"
        . " FROM cm_co_people person"
        . " LEFT OUTER JOIN cm_names name"
        . " ON person.id = name.co_person_id"
        . " AND person.co_person_id IS NULL"
        . " AND NOT name.deleted"
        . " AND name.name_id IS NULL"
        . " LEFT OUTER JOIN cm_email_addresses mail"
        . " ON person.id = mail.co_person_id"
        . " AND NOT mail.deleted"
        . " AND mail.email_address_id IS NULL"
        . " LEFT OUTER JOIN cm_identifiers ident"
        . " ON person.id = ident.co_person_id"
        . " AND ident.identifier_id IS NULL"
        . " AND NOT ident.deleted"
        . " WHERE NOT person.deleted"
        . " AND name.type = 'official'"
        . " AND person.id = :coPersonId"
        . " AND name.primary_name = true"
        . " GROUP BY person.id;";


    private $certQuery = 'SELECT'
        . ' DISTINCT(cert.subject)'
        . ' FROM cm_co_people AS person'
        . ' INNER JOIN cm_co_org_identity_links AS link'
        . ' ON person.id = link.co_person_id'
        . ' AND not link.deleted AND link.co_org_identity_link_id IS NULL'
        . ' AND NOT person.deleted AND person.co_person_id IS NULL'
        . ' INNER JOIN cm_org_identities AS org'
        . ' ON link.org_identity_id = org.id'
        . ' AND org.org_identity_id IS NULL AND NOT org.deleted'
        . ' INNER JOIN cm_certs AS cert'
        . ' ON org.id = cert.org_identity_id'
        . ' AND cert.cert_id IS NULL AND NOT cert.deleted'
        . ' WHERE person.id = :coPersonId'
        . ' AND org.status != \'' . OrgIdentityStatusEnum::Removed . '\'';


    private $termsAgreementRevisionedQuery = "select cctac.id,"
        . " cctac.description,"
        . " cctac.modified,"
        . " cctac.cou_id,"
        . " cctac.url,"
        . " cctac.revision,"
        . " (select (id::text || '::' || co_terms_and_conditions_id::text || '::' || agreement_time::text) as agreement_id_last_agreement_aupid_and_time"
        . " from cm_co_t_and_c_agreements"
        . " where co_person_id = :coPersonId"
        . " and co_terms_and_conditions_id in (select id"
        . " from cm_co_terms_and_conditions"
        . " where co_terms_and_conditions_id = cctac.id)"
        . " order by agreement_time desc"
        . " limit 1) as agreement_id_last_agreement_aupid_time,"
        . " (select revision from cm_co_terms_and_conditions where id = (select co_terms_and_conditions_id"
        . " from cm_co_t_and_c_agreements"
        . " where co_person_id = :coPersonId"
        . " and co_terms_and_conditions_id in (select id"
        . " from cm_co_terms_and_conditions"
        . " where co_terms_and_conditions_id = cctac.id)"
        . " order by agreement_time desc"
        . " limit 1)) as last_aggrement_aupid_revision"
        . " from cm_co_terms_and_conditions as cctac"
        . " inner join cm_co_people ccp on cctac.co_id = ccp.co_id and"
        . " not ccp.deleted and"
        . " ccp.co_person_id is null and"
        . " not cctac.deleted and"
        . " cctac.co_terms_and_conditions_id is null"
        . " where ccp.id = :coPersonId"
        . " and cctac.status = 'A'"
        . " and (cctac.cou_id IN (select ccpr.cou_id"
        . " from cm_co_person_roles as ccpr"
        . " where ccpr.co_person_id = :coPersonId"
        . " and not ccpr.deleted"
        . " and ccpr.co_person_role_id is null"
        . " ) or cctac.cou_id is null)"
        . " and cctac.id NOT IN ("
        . " select distinct cctaca.co_terms_and_conditions_id"
        . " from cm_co_t_and_c_agreements as cctaca"
        . " inner join cm_co_terms_and_conditions c on cctaca.co_terms_and_conditions_id = c.id"
        . " and cctaca.co_person_id = :coPersonId);";


    private $termsAgreementValidQuery = "select cctac.id,"
        . " cctac.description,"
        . " cctac.modified,"
        . " cctac.cou_id,"
        . " cctac.url,"
        . " cctac.revision,"
        . " (select (id::text || '::' || co_terms_and_conditions_id::text || '::' || agreement_time::text) as agreement_id_last_agreement_aupid_and_time"
        . " from cm_co_t_and_c_agreements"
        . " where co_terms_and_conditions_id = cctac.id"
        . " and co_person_id = :coPersonId"
        . " order by agreement_time desc"
        . " limit 1) as agreement_id_last_agreement_aupid_time,"
        . " cctac.revision as last_aggrement_aupid_revision"
        . " from cm_co_terms_and_conditions as cctac"
        . " inner join cm_co_people ccp on cctac.co_id = ccp.co_id and"
        . " not ccp.deleted and"
        . " ccp.co_person_id is null and"
        . " not cctac.deleted and"
        . " cctac.co_terms_and_conditions_id is null"
        . " where ccp.id = :coPersonId"
        . " and cctac.status = 'A'"
        . " and (cctac.cou_id IN ("
        . " select ccpr.cou_id"
        . " from cm_co_person_roles as ccpr"
        . " where ccpr.co_person_id = :coPersonId"
        . " and not ccpr.deleted"
        . " and ccpr.co_person_role_id is null"
        . " ) or cctac.cou_id is null)"
        . " and cctac.id IN ("
        . " select distinct cctaca.co_terms_and_conditions_id"
        . " from cm_co_t_and_c_agreements as cctaca"
        . " inner join cm_co_terms_and_conditions c on cctaca.co_terms_and_conditions_id = c.id"
        . " and cctaca.co_person_id = :coPersonId);";

    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        // Validate Configuration Parameters
        $this->validateConfigParams($config, $this->validateConfigParamRules());

        // Get a copy of the default Roles before enriching with COmanage roles
        // TODO: Move this out configuration check. Make this as part of voRoles multitenacy support
        $voRolesObject = new \ArrayObject($config['voRoles']);
        $this->voRolesDef = $voRolesObject->getArrayCopy();
        $this->orgIdentity = new User\OrgIdentity();
    }

    public function process(&$state)
    {
        try {
            assert('is_array($state)');
            if (isset($state['SPMetadata']['entityid']) && in_array($state['SPMetadata']['entityid'], $this->blacklist, true)) {
                Logger::debug("[attrauthcomanage] process: Skipping blacklisted SP ". var_export($state['SPMetadata']['entityid'], true));
                return;
            }
            if (empty($state['Attributes'][$this->userIdAttribute])) {
                Logger::error("[attrauthcomanage] Configuration error: 'userIdAttribute' not available");
                $this->showError(
                    "attrauthcomanage:attrauthcomanage:exception_USERIDATTRIBUTE_NOTAVAILABLE");
            }

            // XXX finalize the configurations now that we have the final CO Id value
            $this->voGroupPrefix = !empty($this->voGroupPrefix[$this->coId])
                                   ? $this->voGroupPrefix[$this->coId]
                                   : $this->constructGroupPrefix($this->coId);

            unset($state['Attributes']['uid']);
            $orgId = $state['Attributes'][$this->userIdAttribute][0];
            Logger::debug("[attrauthcomanage] process: orgId=" . var_export($orgId, true));
            $basicInfo = $this->getBasicInfo($orgId);
            Logger::debug("[attrauthcomanage] process: basicInfo=". var_export($basicInfo, true));
            if (!empty($basicInfo)) {
                $state['basicInfo'] = $basicInfo;
            }


            if (empty($basicInfo['id'])                                                   // User is NOT present in the Registry OR
                || empty($basicInfo['status'])                                            // User has no status in the Registry OR
               ) {

                // XXX User is eligible to proceed to service
                $state['UserID'] = $orgId;
                $state['ReturnProc'] = [get_class($this), 'retrieveCOPersonData'];
                $params = [];
                $id = State::saveState($state, 'attrauthcomanage:register');
                $callback = Module::getModuleURL('attrauthcomanage/idp_callback.php', ['stateId' => $id]);
                Logger::debug("[attrauthcomanage] process: callback url => " . $callback);
                $params = ["targetnew" => $callback];
                // Check if community signup is required
                if (
                    !empty($state['saml:AuthenticatingAuthority'])
                    && (in_array(end($state['saml:AuthenticatingAuthority']), $this->communityIdps, true)
                        || !empty(array_intersect($this->getIdPTags($this->getIdPMetadata($state)), $this->communityIdpTags))
                       )
                ) {
                    // Redirect to community signup flow with all
                    // attributes available including affiliation
                    if (
                        empty($this->registryUrls['community_sign_up_no_aff'])
                        || (!empty($state['Attributes']['voPersonExternalAffiliation'])
                        && !empty($state['Attributes']['mail'])
                        && !empty($state['Attributes']['givenName'])
                        && !empty($state['Attributes']['sn']))
                    ) {
                        // Redirect to default community signup flow if
                        // 1. there is no other specific community signup defined
                        // or
                        // 2. all signup attributes are available, including affiliation
                        HTTP::redirectTrustedURL($this->registryUrls['community_sign_up'], $params);
                    } else {
                        HTTP::redirectTrustedURL($this->registryUrls['community_sign_up_no_aff'], $params);
                    }
                }
                $this->_redirect($basicInfo, $state, $params);
            }

          // XXX User is Suspended
          if ($basicInfo['status'] === StatusEnum::Suspended) {                     // User is SUSPENDED
            // Redirect to User notification
            $pt_noty = [
              'level' => 'error',
              'description' => ['user_suspended' => [
                '%ORGID%' => $orgId,
              ]],
              'status' => 'user_suspended_title', // This is a dictionary key
              'yes_btn_show' => false,
            ];
            $this->showNoty($pt_noty, $state);
          }
          // XXX Petition in Pending Confirmation
          if ($basicInfo['status'] === StatusEnum::PendingConfirmation) {           // User is PENDING CONFIRMATION
            // Get Petition Id
            $petition_cfg = [
              'enrollee_co_person_id'   => (int)$basicInfo['id'],
              'petition_status'         => $basicInfo['status'],
              'orgIdentifier'           => $state['Attributes'][$this->userIdAttribute][0],
              'co_id'                   => $this->coId,
            ];
            $petition_handler = new Enrollment\PetitionHandler($petition_cfg);
            $petition = $petition_handler->getPetitionFromPersonIdPetStatus();
            $endpoint = str_replace('%id%',
                                    $petition[0]['petition_id'],
                                    EndpointCmgEnum::ConfirmationEmailResend);
            $state['rciamAttributes']['comanage_api_user'] = [
              'username' => $this->comanage_api_username,
              'password' => $this->comanage_api_password,
            ];
            if(!empty($petition)) {
              // Get petition id and redirect to email view
              $pt_noty = [
                'level' => $petition_handler->getBannerClass(),
                'description' => $petition_handler->getUserNotify(),
                'title' => 'resend_confirmation_email',
                //'status' => 'account_pending_confirmation', // This is a dictionary key
                'icon' => 'email.gif',
                'yes_btn_show' => true,
                'form_fields' => [
                  'send_endpoint' => $endpoint,
                  'mail' => $petition[0]['mail'],
                ],
              ];
              $this->showNoty($pt_noty, $state);
            }
          }


          if($basicInfo['status'] !== StatusEnum::Active
            && $basicInfo['status'] !== StatusEnum::GracePeriod) {
            // Redirect to User notification
            $pt_noty = [
              'level' => 'error',
              'description' => ['user_error' => [
                '%ORGID%' => $orgId,
              ]],
              'status' => 'user_error_title', // This is a dictionary key
              'yes_btn_show' => false,
            ];
            $this->showNoty($pt_noty, $state);
          }

          // Record the login
            $auth_event = new User\AuthenticationEventHandler();
            $auth_event->recordAuthenticationEvent($state['Attributes'][$this->userIdAttribute][0]);
            $this->orgIdentity->setOrgIdentityIdentifier($orgId);
            $job_data = $state['Attributes'];
            $this->orgIdentity->insertJobToComanage($this->coId, $orgId, $job_data);
            // Get all the data from the COPerson and import them in the state
            $this->retrieveCOPersonData($state);
        } catch (Error\Error $e) {
            $e->show();
        }
    }

    private function _redirect($basicInfo, &$state, $params = [])
    {
        $attributes = $state['Attributes'];
        Logger::debug("[attrauthcomanage] _redirect: attributes="
            . var_export($attributes, true));
        // Check Pending Confirmation (PC) / Pending Approval (PA) status
        // TODO: How to deal with 'Expired' accounts?
        if (!empty($basicInfo) && ($basicInfo['status'] === 'PC' || $basicInfo['status'] === 'PA')) {
            HTTP::redirectTrustedURL($this->registryUrls['registry_login']);
        }
        if (!empty($attributes['eduPersonScopedAffiliation'])
            && !empty($attributes['mail'])
            && !empty($attributes['givenName'])
            && !empty($attributes['sn'])) {
            HTTP::redirectTrustedURL($this->registryUrls['self_sign_up'], $params);
        }
        HTTP::redirectTrustedURL($this->registryUrls['sign_up'], $params);
    }

    private function getBasicInfo($orgId)
    {
        Logger::debug("[attrauthcomanage] getBasicInfo: orgId="
            . var_export($orgId, true));

        $db = Database::getInstance();
        $queryParams = [
            'coId'          => [$this->coId, PDO::PARAM_INT],
            'coPersonOrgId' => [$orgId, PDO::PARAM_STR],
        ];
        $stmt = $db->read($this->basicInfoQuery, $queryParams);
        if ($stmt->execute()) {
            if ($result = $stmt->fetch(PDO::FETCH_ASSOC)) {
                Logger::debug("[attrauthcomanage] getBasicInfo: result="
                    . var_export($result, true));
               return $result;
            }
        } else {
            throw new Error\Error(
                ['UNHANDLEDEXCEPTION', 'Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true)]
            );
        }

        return null;
    }

    /**
     * @param integer $personId The ID of the CO Person in COmanage
     * @param string $identifier_type The type of identifier
     *
     * @return mixed|null
     * @throws Exception
     * @todo add the Identifier types in the dictionary
     */
    private function getCoPersonIdentifier($personId, $identifier_type)
    {
        Logger::debug("[attrauthcomanage] getCoPersonIdentifier: personId="
            . var_export($personId, true));

        $db = Database::getInstance();
        $queryParams = [
            'coPersonId'     => [$personId, PDO::PARAM_INT],
            'coPersonIdType' => [$identifier_type, PDO::PARAM_STR],
        ];
        $stmt = $db->read($this->coPersonIdentQuery, $queryParams);
        if ($stmt->execute()) {
            if ($result = $stmt->fetch(PDO::FETCH_ASSOC)) {
                Logger::debug("[attrauthcomanage] getCoPersonIdentifier: result="
                    . var_export($result, true));
               return $result['identifier'];
            }
        } else {
            throw new Error\Error(
                ['UNHANDLEDEXCEPTION', 'Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true)]
            );
        }

        return null;
    }


    /**
     * Execute the profileQuery and construct the result set
     * #,name,family,mail_id,mail,verified,identifier,edupersonscopedaffiliation,org_mail_verifed
     * CO Person name
     * CO Person family name
     * CO Person csv of mail ids/mail/verified flag
     * CO Person identifer
     * Org Identities csv of edupersonscopedaffiliation
     * Org Identities csv of verified emails
     *
     * @param integer $personId
     *
     * @return array|null
     * @throws Exception
     */
    private function getProfile($personId)
    {
        Logger::debug("[attrauthcomanage] getProfile: personId="
            . var_export($personId, true));

        $db = Database::getInstance();
        $queryParams = [
            'coPersonId' => [$personId, PDO::PARAM_INT],
        ];
        $stmt = $db->read($this->profileQuery, $queryParams);
        if ($stmt->execute()) {
            $result = [];
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            Logger::debug("[attrauthcomanage] getProfile: result="
                . var_export($result, true));
            return $result;
        } else {
            throw new Error\Error(
                ['UNHANDLEDEXCEPTION', 'Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true)]
            );
        }

        return null;
    }

    /**
     * Get and construct the profile of the COPerson.
     * The profile includes the attributes:
     * given, sn, mail, voPersonVerifiedEmail, eduPersonScopedAffiliation, uid
     *
     * @param array &$state
     * @param integer $co_person_id
     * @return boolean
     * @throws Exception
     */
    private function constructProfile(&$state, $co_person_id)
    {
        $profile = $this->getProfile($co_person_id);
        if (empty($profile)) {
            return false;
        }
        foreach ($profile as $attributes) {
            if (!empty($attributes['given'])) {
                $state['Attributes']['givenName'] = [$attributes['given']];
            }
            if (!empty($attributes['family'])) {
                $state['Attributes']['sn'] = [$attributes['family']];
            }
            if (!empty($attributes['mail'])) {
                // Sort the mails by their row unique id(lowest to highest
                $mails = explode(',', $attributes['mail']);
                $mails = array_filter($mails);
                $pmail_list = [];
                foreach($mails as $mail) {
                    list($id, $email, $verified) = explode(':', $mail);
                    $pmail_list[$id] = [$email => filter_var($verified, FILTER_VALIDATE_BOOLEAN)];
                }
                // XXX Sort and keep only the email and verified status.
                $pmail_sorted_list = [];
                if (ksort($pmail_list)) {
                    foreach($pmail_list as $sorted_mails) {
                        foreach($sorted_mails as $email => $verified) {
                            $pmail_sorted_list[$email] = $verified;
                        }
                    }
                }
                // Get the oldest email in CO Person's profile
                $pmail_sorted_list_keys = array_keys($pmail_sorted_list);
                $state['Attributes']['mail'] = [array_shift($pmail_sorted_list_keys)];
                // XXX for the voPersonVerifiedEmail attribute we need an array with all the verified emails
                $verified_mail_list = array_filter(
                    $pmail_sorted_list,
                    static function ($verified, $mail) {
                        return $verified === true;
                    }, ARRAY_FILTER_USE_BOTH
                );
                if (!empty($verified_mail_list)) {
                    $state['Attributes']['voPersonVerifiedEmail'] = array_keys($verified_mail_list);
                }
            }
            if (!empty($attributes['edupersonscopedaffiliation'])) {
                $state['Attributes']['eduPersonScopedAffiliation'] = explode(
                    ',',
                    $attributes['edupersonscopedaffiliation']
                );
                // XXX Remove any duplicate edupersonscopedaffiliation
                $state['Attributes']['eduPersonScopedAffiliation'] = array_filter(array_unique($state['Attributes']['eduPersonScopedAffiliation']));
            }
            if (!empty($attributes['identifier'])) {
                $identifiers = explode(',', $attributes['identifier']);
                foreach ($identifiers as $ident) {
                    $ident_key_val = explode(':', $ident, 2);
                    if(!empty($this->attrMap)
                        && array_key_exists($ident_key_val[0], $this->attrMap)) {
                        $attribute_key = $this->attrMap[$ident_key_val[0]];
                    } else {
                        $attribute_key = $ident_key_val[0];
                        Logger::debug("[attrauthcomanage] constructProfile: No attrMap mapping found for COmanage attribute:"
                                                 . var_export($ident_key_val,true));
                    }
                    if( array_key_exists($attribute_key,$state['Attributes'])
                        && !in_array($ident_key_val[1], $state['Attributes'][$attribute_key], true)) {
                        $state['Attributes'][$attribute_key][] = $ident_key_val[1];
                    } else {
                        $state['Attributes'][$attribute_key] = [$ident_key_val[1]];
                    }
                }
            }
        }
        Logger::debug("[attrauthcomanage] constructProfile: profile="
                                 . var_export($state['Attributes'], true));

        return true;
    }

    private function getCerts($personId)
    {
        Logger::debug("[attrauthcomanage] getCerts: personId="
            . var_export($personId, true));

        $result = [];
        $db = Database::getInstance();
        $queryParams = [
            'coPersonId' => [$personId, PDO::PARAM_INT],
        ];
        $stmt = $db->read($this->certQuery, $queryParams);
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            Logger::debug("[attrauthcomanage] getCerts: result="
                . var_export($result, true));
            return $result;
        } else {
            throw new Error\Error(
                ['UNHANDLEDEXCEPTION', 'Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true)]
            );
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
     * @uses Logger::debug
     * @uses Database::getInstance
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
            . " AND role.status IN ('A', 'GP')"
            . " AND NOT role.deleted AND role.co_person_id = members.co_person_id"
            . " GROUP BY"
            . " groups.name";

        $db = Database::getInstance();
        // Strip the cou_id from the unnecessary characters
        $queryParams = [
            'co_id'        => [$co_id, PDO::PARAM_INT],
            'co_person_id' => [$co_person_id, PDO::PARAM_INT],
        ];
        $result = [];
        $stmt = $db->read($membership_query, $queryParams);
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            Logger::debug("[attrauthcomanage] getMemberships: result="
                . var_export($result, true)
            );
        } else {
            throw new Error\Error(
                ['UNHANDLEDEXCEPTION', 'Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true)]
            );
        }

        return $result;
    }

    /**
     * Returns nested COU path ready to use in an AARC compatible entitlement
     * @param array $cous
     * @param array $nested_cous_paths
     * @throws RuntimeException Failed to communicate with COmanage database
     * @uses Logger::debug
     * @uses Database::getInstance
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

        $db = Database::getInstance();
        foreach ($cous as $cou) {
            if (empty($cou['group_name']) || empty($cou['cou_id'])) {
                continue;
            }
            // Strip the cou_id from the unnecessary characters
            $queryParams = [
                'cou_id' => [$cou['cou_id'], PDO::PARAM_INT],
            ];
            $stmt        = $db->read($recursive_query, $queryParams);
            if ($stmt->execute()) {
                while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                    if (strpos($row['path'], ':') !== false) {
                        $path_group_list   = explode(':', $row['path']);
                        $path_group_list   = array_map(
                            function ($group) {
                                return urlencode($group);
                            },
                            $path_group_list
                        );
                        $nested_cous_paths += [
                            $cou['cou_id'] => [
                                'path'           => implode(':', $path_group_list),
                                'path_id_list'   => explode(':', $row['path_id']),
                                'path_full_list' => array_combine(
                                    explode(':', $row['path_id']), // keys
                                    $path_group_list               // values
                                ),
                            ],
                        ];
                    }
                }
            } else {
                throw new \RuntimeException(
                    'Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true)
                );
            }
        }
        Logger::debug("[attrauthcomanage] getCouTreeStructure: nested_cous_paths=" . var_export($nested_cous_paths, true));
    }

    /**
     * Add eduPersonEntitlements in the State(no filtering happens here.)
     * @param array $personRoles
     * @param array &$state
     * @param string $vo_name
     * @param string $group_name
     * @param array $memberEntitlements
     * @param integer $cou_id
     * @param array $cou_tree_structure
     * @todo Remove old style entitlements
     * @todo Remove $group_name variable
     */
    private function couEntitlementAssemble($personRoles, &$state, $vo_name, $group_name = "", &$memberEntitlements = null, $cou_id = null, $cou_tree_structure = array())
    {
      foreach ($personRoles as $key => $role) {
        // We need this to filter the cou_id or any other irrelevant information
        if (is_string($key) && $key === 'cou_id') {
          continue;
        }
        // Do not create entitlements for the admins group here.
        if (strpos($vo_name, ':admins') !== false) {
          continue;
        }
        if (!empty($role) && is_array($role) && count($role) > 0) {
          $this->couEntitlementAssemble($role, $state, $vo_name, $key, $memberEntitlements, $personRoles['cou_id'], $cou_tree_structure);
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

        if(!empty($personRoles['cou_id'])
           && ( !in_array($role, $this->voRolesDef) || in_array($role, $this->voRolesInter) )
           && !empty($cou_tree_structure[ $personRoles['cou_id'] ])) {
          $this->EntitlementsToRemove[] = $entitlement;
          $state['Attributes']['eduPersonEntitlement'][] =
            $this->urnNamespace                                       // URN namespace
            . ":group:"                                               // group literal
            . $cou_tree_structure[ $personRoles['cou_id'] ]['path']   // Nested VO
            . $group . ":role=" . $role                               // role
            . "#" . $this->urnAuthority;                              // AA FQDN
        }

        // TODO: remove in the near future
        if ($this->urnLegacy) {
            $state['Attributes']['eduPersonEntitlement'][] =
                  $this->urnNamespace          // URN namespace
                  . ':' . $this->urnAuthority  // AA FQDN
                  . $group . ':' . $role       // role
                  . "@"                        // VO delimiter
                  . urlencode($vo_name);       // VO
        } // Deprecated syntax

        if ($this->noRoleEntitlements) {
            $state['Attributes']['eduPersonEntitlement'][] = 
                  $this->urnNamespace // URN namespace
                  . ':' . 'group:' 
                  . urlencode($vo_name) // VO
                  . '#'. $this->urnAuthority; 
        }
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
        Logger::debug("[attrauthcomanage] mergeEntitlements: member_entitlements="
            . var_export($member_entitlements, true));
        Logger::debug("[attrauthcomanage] mergeEntitlements: cou_tree_structure="
            . var_export($cou_tree_structure, true));
        Logger::debug("[attrauthcomanage] mergeEntitlements: orphan_memberships="
            . var_export($orphan_memberships, true));

        if (empty($cou_tree_structure) || empty($member_entitlements)) {
            return;
        }

        // Retrieve only the entitlements that need handling.
        $filtered_cou_ids = [];
        foreach ($cou_tree_structure as $node) {
            $filtered_cou_ids[] = $node['path_id_list'];
        }
        $filtered_cou_ids = array_values(array_unique(array_merge(...$filtered_cou_ids)));
        Logger::debug("[attrauthcomanage] mergeEntitlements: filtered_cou_ids="
            . var_export($filtered_cou_ids, true));

        // XXX Get the COU ids that also have an admin role
        $filtered_admin_cou_ids = !empty($member_entitlements['admins']) ? array_keys($member_entitlements['admins']) : [];
        Logger::debug("[attrauthcomanage] mergeEntitlements: filtered_admin_cou_ids="
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
        Logger::debug("[attrauthcomanage] mergeEntitlements: filtered_entitlements="
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
                    $full_candidate_entitlement = implode(':', $cou_name_hierarchy);
                    $cou_id_hierarchy = array_slice($sub_tree['path_id_list'], 0, $key + 1);
                    $full_candidate_cou_id = implode(':', $cou_id_hierarchy);
                }
            }
            if (!empty($full_candidate_cou_id) && !empty($full_candidate_entitlement)) {
                $list_of_candidate_full_nested_groups[$full_candidate_cou_id] = $full_candidate_entitlement;
            }
        }

        Logger::debug("[attrauthcomanage] mergeEntitlements: list_of_candidate_full_nested_groups="
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
        foreach ($cou_tree_structure as $cou_id => $sub_tree) {
            // XXX Split the full path and encode each part.
            $parent_vo = array_values($sub_tree['path_full_list'])[0];
            if (isset($this->voWhitelist) && !in_array($parent_vo, $this->voWhitelist, true)) {
                continue;
            }
            // XXX Also exclude the ones that are admin groups
            $cou_exist = array_filter($this->coGroupMemberships, static function($membership) use ($cou_id){
                return (!empty($membership['cou_id'])
                    && (integer)$membership['cou_id'] === $cou_id
                    && (!empty($membership['affiliation']) || !empty($membership['title'])));
            });
            if (empty($cou_exist)) {
                continue;
            }

            foreach ($this->voRolesDef as $role) {
                $entitlement =
                    $this->urnNamespace              // URN namespace
                    . ":group:"                      // group literal
                    . $parent_vo                     // VO
                    . ":role=" . $role               // role
                    . "#" . $this->urnAuthority;     // AA FQDN

                $state['Attributes']['eduPersonEntitlement'][] = $entitlement;
            }
        }

        // XXX Add all orphan admins COU groups in the state
        foreach ($orphan_memberships as $membership) {
            Logger::debug("[attrauthcomanage] membeship: membeship=" . var_export($membership, true));
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
                foreach ($membership_roles as $role) {
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

        // XXX Remove single level entitlements marked to be removed
        foreach($this->EntitlementsToRemove as $ent) {
          foreach($state['Attributes']['eduPersonEntitlement'] as $idx => $entitlement) {
            if ($ent == $entitlement) {
              unset($state['Attributes']['eduPersonEntitlement'][$idx]);
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
        $orgId = $state['Attributes'][$this->userIdAttribute][0];
        if (isset($state['basicInfo'])) {
            Logger::debug("[attrauthcomanage] retrieveCOPersonData: " . var_export($state['basicInfo'], true));
            $basicInfo = $state['basicInfo'];
        } else {
            $basicInfo = $this->getBasicInfo($orgId);
        }
        // XXX Add CO Person Id in the state
        $state['rciamAttributes']['registryUserId'] = $basicInfo['id'];

        // XXX Check if the Identifier created by UserId module is a login Identifier
        // XXX Scenario: The user ID module creates an Identifier. We must check that this identifier is enlisted
        // XXX in the list of available OrgIdentities of the CO Person and is a valid authenticator.
        // XXX Upon success we return the Identifier of the COPerson
        $this->orgIdentity->setOrgIdentityIdentifier($orgId);
        $orgIdentifiers = $this->orgIdentity->getLoginOrgIdentifiers($basicInfo['id'], $this->coOrgIdType);

        Logger::debug('[attrauthcomanage] process: orgIdentifiers=' . var_export($orgIdentifiers, true));
        if (!empty($orgIdentifiers)) {
            $state['orgIndentifiersList'] = $orgIdentifiers;
        }
        // XXX Check if the identifier is an authenticator
        if (!$this->orgIdentity->isIdpIdentLogin()) {
            // Redirect to User notification
            $pt_noty = [
                'level' => $this->orgIdentity->getBannerClass(),
                'description' => $this->orgIdentity->getUserNotify($state, 'nologin'),
                'status' => 'org_identity_nologin_banner', // This is a dictionary key
                'yes_btn_show' => false,
            ];
            $this->showNoty($pt_noty, $state);
        }
        // XXX Check if the identifier is valid or has expired
        if ($this->orgIdentity->isIdpIdentExpired()) {
            // Redirect to User notification
            $pt_noty = [
                'level' => $this->orgIdentity->getBannerClass(),
                'description' => $this->orgIdentity->getUserNotify($state, 'expired'),
                'status' => 'org_identity_expired_banner', // This is a dictionary key
                'yes_btn_show' => false,
            ];
            $this->showNoty($pt_noty, $state);
        }

        if ($this->orgIdentity->isIdpRemoved()) {
            // Redirect to User notification
            $pt_noty = [
                'level' => $this->orgIdentity->getBannerClass(),
                'description' => $this->orgIdentity->getUserNotify($state, 'removed'),
                'status' => 'org_identity_removed_banner', // This is a dictionary key
                'yes_btn_show' => false,
            ];
            $this->showNoty($pt_noty, $state);
        }

        $loginId = $this->getCoPersonIdentifier($basicInfo['id'], $this->coUserIdType);
        Logger::debug("[attrauthcomanage] retrieveCOPersonData: loginId=" . var_export($loginId, true));

        $state['Attributes'][$this->userIdAttribute] = [$loginId];
        $state['rciamAttributes']['cuid'] = [$loginId];
        // XXX Create shortcuts for the basic USER data
        $state['UserOrgID'] = $orgId;
        $state['UserID'] = $loginId;

        Logger::debug("[attrauthcomanage] retrieveCOPersonData: constructProfile.");
        // XXX Construct the User's profile and add into the state
        if (!$this->constructProfile($state, $basicInfo['id'])) {
            return;
        }

        // XXX Get Certificate information
        if($this->certificate) {
            Logger::debug("[attrauthcomanage] retrieveCOPersonData: certificates.");
            $certs = $this->getCerts($basicInfo['id']);
            foreach($certs as $cert) {
                if(empty($cert['subject'])) {
                    continue;
                }
                if(!array_key_exists($this->certificateDnAttribute, $state['Attributes'])) {
                    $state['Attributes'][$this->certificateDnAttribute] = [];
                }
                if(!in_array($cert['subject'], $state['Attributes'][$this->certificateDnAttribute], true)) {
                    $state['Attributes'][$this->certificateDnAttribute][] = $cert['subject'];
                }
            }
        } else {
            Logger::debug("[attrauthcomanage] retrieveCOPersonData: Skipping certificates.");
        }

        // Get SSH Public Key information
        if($this->retrieveSshKeys) {
            Logger::debug("[attrauthcomanage] retrieveCOPersonData: sshPublicKeys.");
            $attrSshPublicKey = new Attributes\SshPublicKey();
            $sshPublicKeys = $attrSshPublicKey->getSshPublicKeys($basicInfo['id']);
            foreach($sshPublicKeys as $sshKey) {
                if(!empty($sshKey['skey']) && !empty($sshKey['type'])) {
                    $sshPublicKey = $attrSshPublicKey->getSshPublicKeyType($sshKey['type']) . ' ' . $sshKey['skey']
                    . ( !empty($sshKey['comment']) ? ' ' . $sshKey['comment'] : "" );
                    if(!array_key_exists('sshPublicKey', $state['Attributes'])) {
                        $state['Attributes']['sshPublicKey'] = [];
                    }
                    if(!in_array($sshPublicKey, $state['Attributes']['sshPublicKey'], true)) {
                        $state['Attributes']['sshPublicKey'][] = $sshPublicKey;
                    }
                }
            }
        } else {
            Logger::debug("[attrauthcomanage] retrieveCOPersonData: Skipping sshPublicKeys.");
        }

        Logger::debug("[attrauthcomanage] retrieveCOPersonData: Group Memberships.");
        // XXX Get all the memberships from the the CO for the user
        $this->coGroupMemberships = $this->getMemberships($this->coId, $basicInfo['id']);

        // XXX Terms Agreement
        // XXX We rely on memberships for COUs AUPs. Even when we have no memberships we need to construct AUP and then return
        if ($this->retrieveAUP) {
            $termsAgreementRevised = $this->getTermsAgreementRevisioned($basicInfo['id']);
            $termsAgreementValid = $this->getTermsAgreementValid($basicInfo['id']);
            // Construct the AUP model and append it into the state, $state['aup']
            $this->constructAupStatus($termsAgreementValid, $termsAgreementRevised, $this->coGroupMemberships, $state);
        }
        // XXX if this is empty return
        if (empty($this->coGroupMemberships)) {
            return;
        }
        // XXX Extract the group memberships
        $group_memberships = array_filter(
            $this->coGroupMemberships,
            static function ($value) {
                if (is_null($value['cou_id'])) {
                    return $value;
                }
            }
        );
        Logger::debug("[attrauthcomanage] group_memberships=" . var_export($group_memberships, true));

        // XXX Extract the cou memberships
        // TODO: Make some more clearance here. Remove also thn VOs that should have an entitlement. Be carefull about multi tenacy
        // TODO: This needs the voWhitelist which should be a configuration per CO
        // XXX This will make things simpler and faster below
        $cou_memberships = array_filter(
            $this->coGroupMemberships,
            static function ($value) {
                if (!is_null($value['cou_id'])) {
                    return $value;
                }
            }
        );
        Logger::debug("[attrauthcomanage] cou_memberships=" . var_export($cou_memberships, true));


        Logger::debug("[attrauthcomanage] retrieveCOPersonData: groupEntitlemeAssemble.");
        // XXX Construct the plain group Entitlements
        $this->groupEntitlemeAssemble($state, $group_memberships, $this->voGroupPrefix);

        // XXX Get the Nested COUs for the user
        $nested_cous = [];
        $this->getCouTreeStructure($cou_memberships, $nested_cous);

        // Define the array that will hold the member entitlements
        $members_entitlements = [];
        // Temp list of entitlements to remove
        $this->EntitlementsToRemove = array();
        // Iterate over the COUs and construct the entitlements
        foreach ($cou_memberships as $idx => $cou) {
            if (empty($cou['group_name'])) {
                continue;
            }
            $vo_roles = [];
            if (isset($this->voWhitelist) && !in_array($cou['group_name'], $this->voWhitelist, true)) {
                // XXX Check if there is a root COU that is in the voWhitelist
                // XXX :admins this is not part of the voWhiteList that's why i do not get forward
                $parent_cou_name = $this->getCouRootParent($cou['group_name'], $nested_cous);
                if (isset($this->voWhitelist)
                    && !in_array($parent_cou_name, $this->voWhitelist, true)
                    && strpos($cou['group_name'], ':admins') === false) {
                    // XXX Remove a child COU that has no parent in the voWhitelist OR
                    // XXX Remove if it does not represent an admins group AND
                    unset($cou_memberships[$idx]);
                    continue;
                }
                if (isset($this->voWhitelist)
                    && !in_array($parent_cou_name, $this->voWhitelist, true)
                    && !strpos($cou['group_name'], ':admins') === false) {
                    continue;
                }
            }
            if (!array_key_exists('eduPersonEntitlement', $state['Attributes'])) {
                $state['Attributes']['eduPersonEntitlement'] = [];
            }

            $voName = $cou['group_name'];
            Logger::debug("[attrauthcomanage] voName=" . var_export($voName, true));

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
            // Find the intersection of default and VO roles
            $this->voRolesInter = array_intersect($vo_roles, $this->voRoles);
            // Merge the default roles with the ones constructed from the COUs
            $vo_roles = array_unique(array_merge($vo_roles, $this->voRoles));
            // Get the admins group if exists
            $cou_admins_group = array_values(
                array_filter(
                    $cou_memberships,
                    static function ($value) use ($voName) {
                        if ($value['group_name'] === ($voName . ':admins')) {
                            return $value;
                        }
                    }
                )
            );

            Logger::debug("[attrauthcomanage] cou_admins_group=" . var_export($cou_admins_group, true));
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

            Logger::debug("[attrauthcomanage] retrieveCOPersonData voRoles[{$voName}]=" . var_export($vo_roles, true));
            $this->couEntitlementAssemble($vo_roles, $state, $voName, "", $members_entitlements, null, $nested_cous);
            // XXX Remove the ones already done
            unset($cou_memberships[$idx]);
        } // foreach cou

        // Fix nested COUs entitlements
        $this->mergeEntitlements($nested_cous, $members_entitlements, $state, $cou_memberships);

        if (!empty($state['Attributes']['eduPersonEntitlement'])) {
            Logger::debug("[attrauthcomanage] retrieveCOPersonData AFTER: eduPersonEntitlement=" . var_export($state['Attributes']['eduPersonEntitlement'], true));
        }
    }

    /**
     * Construct AUP status model
     * {
     *   "aup":
     *     [
     *       {
     *         "id":"<cm_co_terms_and_conditions::id>", // AUP ID
     *         "description":"<cm_co_terms_and_conditions::description>", // AUP description
     *         "modified":"<cm_co_terms_and_conditions::modified>", // AUP modification timestamp
     *         "url":"cm_co_terms_and_conditions::url", // AUP content
     *         "vo": // null when AUP is not VO-specific
     *         {
     *           "id":"<cm_cous::id>", // VO ID
     *           "name":"<cm_cous::name>" // VO name
     *         },
     *         "version":cm_co_terms_and_conditions::revision, // AUP current version
     *         "agreed": // AUP user agreement information; null if there is no agreement
     *         {
     *           "id": "<cm_co_t_and_c_agreements::id>", // Id of agreement
     *           "aupId":"<cm_co_t_and_c_agreements::co_terms_and_conditions_id>", // Latest AUP ID agreed
     *           "date":"<cm_co_t_and_c_agreements::agreement_time>" // Date of agreement
     *           "version":" <cm_co_t_and_c_agreements::cm_co_terms_and_conditions_id::revision>" // AUP agreed version
     *         },
     *       }
     *     ]
     *   }
     *
     * @param array $accepted_aup
     * @param array $pending_aup
     * @param array $co_memberships
     * @param array $state
     */
    private function constructAupStatus($accepted_aup, $pending_aup, $co_memberships, &$state)
    {
        $state['rciamAttributes']['aup'] = [];
        if (empty($accepted_aup)) {
            $accepted_aup = [];
        }
        if (empty($pending_aup)) {
            $pending_aup = [];
        }

        $all_aups = array_merge($accepted_aup, $pending_aup);

        if (empty($all_aups)) {
            return;
        }

        foreach($all_aups as $aup) {
            $tmp = [];
            $tmp['id'] = $aup['id'];
            $tmp['description'] = $aup['description'];
            $tmp['modified'] = $aup['modified'];
            $tmp['url'] = $aup['url'];
            $tmp['version'] = $aup['revision'];
            $tmp['vo'] = null;
            if (!empty($aup['cou_id']) && $aup['cou_id'] > 0) {
                $tmp['vo'] = [];
                $tmp['vo']['id'] = $aup['cou_id'];
                $cou_id = $aup['cou_id'];
                // first we should check if user is still member of the COU related to accepted AUP
                // as he/she may has been expired
                $is_member = array_filter(
                    $co_memberships,
                    static function($group) use ($cou_id) {
                        if ((int)$group['cou_id'] === (int)$cou_id) {
                           return true;
                        }
                    }
                );
                // if is not still member then ignore this aup
                if(empty($is_member)){
                    continue;
                }

                $cou = array_filter(
                    $co_memberships,
                    static function($group) use ($cou_id) {
                        if ((int)$group['cou_id'] === (int)$cou_id
                            && strpos($group['group_name'], ':admins') === false) {
                            return $group;
                        }
                    }
                );
                if (!empty($cou)) {
                    // XXX User is COU member
                    $cou = array_values($cou);
                    $tmp['vo']['name'] = $cou[0]['group_name'];
                } else {
                    // XXX User is ONLY COU:admins member
                    $group = array_filter(
                        $co_memberships,
                        static function($group) use ($cou_id) {
                            if ((int)$group['cou_id'] === (int)$cou_id
                                && strpos($group['group_name'], ':admins') !== false) {
                                return $group;
                            }
                        }
                    );
                    $group = array_values($group);
                    $group_name = explode(':admins', $group[0]['group_name'])[0];
                    $tmp['vo']['name'] = $group_name;
                }
            }
            $tmp['agreed'] = null;
            if (!empty($aup['agreement_id_last_agreement_aupid_time'])) {
                list($tmp['agreed']['id'], $tmp['agreed']['aupId'], $tmp['agreed']['date']) = explode('::', $aup['agreement_id_last_agreement_aupid_time']);
                $tmp['agreed']['version'] = !is_null($aup['last_aggrement_aupid_revision'])
                                            ? $aup['last_aggrement_aupid_revision'] : 0;
            }
            $state['rciamAttributes']['aup'][] = $tmp;
        }
        Logger::debug("[attrauthcomanage] constructAupStatus::state['rciamAttributes']['aup'] => " . var_export($state['rciamAttributes']['aup'], true));

    }

    /**
     * Construct the plain group entitlements. No nesting supported.
     * @param array $state
     * @param array $memberships_groups
     * @param string $groupPrefix
     */
    private function groupEntitlemeAssemble(&$state, $memberships_groups, $groupPrefix)
    {
        if (empty($memberships_groups)) {
            return;
        }
        foreach ($memberships_groups as $group) {
            $roles = [];
            if ($group['member'] === true) {
                $roles[] = "member";
            }
            if ($group['owner'] === true) {
                $roles[] = "owner";
            }
            if (!array_key_exists('eduPersonEntitlement', $state['Attributes'])) {
                $state['Attributes']['eduPersonEntitlement'] = [];
            }

            foreach ($roles as $role) {
                $state['Attributes']['eduPersonEntitlement'][] =
                    $this->urnNamespace                // URN namespace
                    . ":group:" . $groupPrefix . ":"   // Group Prefix
                    . urlencode($group['group_name'])  // VO
                    . ":role=" . $role                 // role
                    . "#" . $this->urnAuthority;       // AA FQDN
                // Enable legacy URN syntax for compatibility reasons?
                if ($this->urnLegacy) {
                    $state['Attributes']['eduPersonEntitlement'][] =
                        $this->urnNamespace                  // URN namespace
                        . ':' . $this->urnAuthority          // AA FQDN
                        . ':' . $role                        // role
                        . "@"                                // VO delimiter
                        . urlencode($group['group_name']);   // VO
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
     * Construct the Group Prefix for COmanage Plain Groups as defined in AARC
     * @param integer $co_id
     * @return string
     */
    private function constructGroupPrefix($co_id) {
        $co_query ="select name from cm_cos where id=:co_id and status='A';";

        $db = Database::getInstance();
        // Strip the cou_id from the unnecessary characters
        $queryParams = [
            'co_id' => [$co_id, PDO::PARAM_INT],
        ];
        $stmt = $db->read($co_query, $queryParams);
        $co_name = '';
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $co_name = urlencode($row['name']);
            }
        } else {
            throw new \RuntimeException('Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true));
        }
        Logger::debug("[attrauthcomanage] constructGroupPrefix: " . var_export($co_name . ":group", true));
        return $co_name . ':group';
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

    /**
     * Column Names [id, description, modified, cou_id, url, revision, last_aggrement_aupid_and_time(id::agreement_time)]
     * id(cm_co_terms_and_conditions):                              ID in the database of the Terms and Conditions entry
     * description(cm_co_terms_and_conditions):                     Short description of the T&C entry
     * modified(cm_co_terms_and_conditions):                        The date of latest update
     * cou_id(cm_co_terms_and_conditions):                          null if not related to a COU an integer of the COU id otherwise
     * url(cm_co_terms_and_conditions):                             the url of the Terms&Condition document
     * revision(cm_co_terms_and_conditions):                        Indicates the number of times this T&C was revised
     * last_aggrement_aupid_and_time(cm_co_t_and_c_agreements):     co_terms_and_conditions_id::agreement_time pair of the last accepted T&C and the exact date of acceptance
     *
     * @param integer $personId
     *
     * @return array
     * @throws Exception
     *
     */
    private function getTermsAgreementValid($personId)
    {
        Logger::debug("[attrauthcomanage] getTermsAgreement: personId="
            . var_export($personId, true));

        $result = [];
        $db = Database::getInstance();
        $queryParams = [
            'coPersonId' => [$personId, PDO::PARAM_INT],
        ];
        $stmt = $db->read($this->termsAgreementValidQuery, $queryParams);
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            Logger::debug("[attrauthcomanage] getTermsAgreementValid: result="
                . var_export($result, true));
            return $result;
        } else {
            throw new Error\Error(
                ['UNHANDLEDEXCEPTION', 'Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true)]
            );
        }

        return $result;
    }

    /**
     * Column Names [id, description, modified, cou_id, url, revision, last_aggrement_aupid_and_time(id::agreement_time)]
     * id(cm_co_terms_and_conditions):                              ID in the database of the Terms and Conditions entry
     * description(cm_co_terms_and_conditions):                     Short description of the T&C entry
     * modified(cm_co_terms_and_conditions):                        The date of the latest update
     * cou_id(cm_co_terms_and_conditions):                          null if not related to a COU an integer of the COU id otherwise
     * url(cm_co_terms_and_conditions):                             the url of the Terms&Condition document
     * revision(cm_co_terms_and_conditions):                        Indicates the number of times this T&C was revised
     * last_aggrement_aupid_and_time(cm_co_t_and_c_agreements):     co_terms_and_conditions_id::agreement_time pair of the last accepted T&C and the exact date of acceptance
     *
     * @param integer $personId
     *
     * @return array
     * @throws Exception
     *
     */
    private function getTermsAgreementRevisioned($personId)
    {
        Logger::debug("[attrauthcomanage] getTermsAgreementRevisioned: personId="
            . var_export($personId, true));

        $result = [];
        $db = Database::getInstance();
        $queryParams = [
            'coPersonId' => [$personId, PDO::PARAM_INT],
        ];
        $stmt = $db->read($this->termsAgreementRevisionedQuery, $queryParams);
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            Logger::debug("[attrauthcomanage] getTermsAgreementRevisioned: result="
                . var_export($result, true));
            return $result;
        } else {
            throw new Error\Error(
                ['UNHANDLEDEXCEPTION', 'Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true)]
            );
        }

        return $result;
    }

    /**
     * @param $config
     * @param $validateConfigParamRules
     *
     * @throws Error\Exception
     */
    private function validateConfigParams($config, $validateConfigParamRules) {
        if(empty($config) || empty($validateConfigParamRules)) {
            Logger::error("[attrauthcomanage] Config or validation Rules are missing.");
            $this->showError(
                "attrauthcomanage:attrauthcomanage:exception_CONFIG_VALIDATION_RULES_MISSING");
        }

        foreach ($validateConfigParamRules as $req_opt_key => $validation_list) {
            if($req_opt_key === 'required') {
                /*
                 * MANDATORY ATTRIBUTES
                 */
                foreach($validation_list as $req_attr => $validation_rules) {
                    if (!array_key_exists($req_attr, $config)) {
                        Logger::error("[attrauthcomanage] Configuration error: '" . $req_attr . "' not specified");
                        $this->showError(
                            "attrauthcomanage:attrauthcomanage:exception_ATTRIBUTE_NOT_SPECIFIED",  ['%REQATTR%' => $req_attr]);
                    }
                    if (!$validation_rules['type']($config[$req_attr])) {
                        Logger::error("[attrauthcomanage] Configuration error: '" . $req_attr . "' wrong format(array required)");
                        $this->showError(
                            "attrauthcomanage:attrauthcomanage:exception_ATTRIBUTE_WRONG_FORMAT", ['%REQATTR%' => $req_attr]);
                    }
                    if(array_key_exists('key_list', $validation_rules)) {
                        $required_key_values = array_values($validation_rules['key_list']);
                        $provided_keys = array_keys($config[$req_attr]);
                        $non_provided_keys = [];
                        foreach ($required_key_values as $req_key) {
                            if (!in_array($req_key, $provided_keys)) {
                                $non_provided_keys[] = $req_key;
                            }
                        }
                        if (!empty($non_provided_keys) ) {
                            Logger::error("[attrauthcomanage] Configuration error:'" . $req_attr
                                                     . "' key configuration errorRequired keys missing:"
                                                     . implode(',', $non_provided_keys));
                            $this->showError("attrauthcomanage:attrauthcomanage:exception_ATTRIBUTE_KEY_CONFIGURATION_ERROR", ['%REQATTR%' => $req_attr, '%NONKEYS%' => implode(',', $non_provided_keys)]);
                        }

                    }
                    if(array_key_exists('value_filter',$validation_rules)) {
                        $invalid_values = [];
                        foreach ($config[$req_attr] as $value) {
                            if(!filter_var($value, $validation_rules['value_filter'])) {
                                $invalid_values[] = $value;
                            }
                        }
                        if (!empty($invalid_values) ) {
                            Logger::error("[attrauthcomanage] Configuration error:'" . $req_attr . "' invalid value");
                            $this->showError(
                                "attrauthcomanage:attrauthcomanage:exception_ATTRIBUTE_INVALID_VALUE", ['%REQATTR%' => $req_attr]);
                        }

                    }

                    $this->$req_attr=$config[$req_attr];
                }
            } elseif ($req_opt_key === 'optional') {
                /*
                 *  OPTIONAL ATTRIBUTES
                 */
                foreach($validation_list as $opt_attr => $type) {
                    if (array_key_exists($opt_attr, $config)) {
                        if (!$type($config[$opt_attr])) {
                            Logger::error("[attrauthcomanage] Configuration error: " . $opt_attr . " not of type " . $type);
                            $this->showError(
                                "attrauthcomanage:attrauthcomanage:exception_ATTRIBUTE_NOT_BOOLEAN", ['%OPTATTR%' => $opt_attr]);
                        }
                        $this->$opt_attr = $config[$opt_attr];
                    }
                }
            }
        }
    }


    /**
     * Array of validation rules for the config params.
     * Make changes here and not in the constructor
     *
     * @return string[][]
     */
    private function validateConfigParamRules() {
        return [
            'required' => [
                'coId' => [
                    'type' => 'is_int'
                ],
                'urnNamespace' => [
                    'type' => 'is_string'
                ],
                'voRoles' => [
                    'type' => 'is_array'
                ],
                'urnAuthority' => [
                    'type' => 'is_string'
                ],
                'registryUrls' => [
                    'type' => 'is_array',
                    'key_list' => [
                        'self_sign_up',
                        'sign_up',
                        'community_sign_up',
                        'registry_login'
                    ],
                    'value_filter' => FILTER_VALIDATE_URL,
                ],
            ],
            'optional' => [
                'attrMap' => 'is_array',
                'coOrgIdType' => 'is_array',
                'blacklist' => 'is_array',
                'voWhitelist' => 'is_array',
                'communityIdps' => 'is_array',
                'communityIdpTags' => 'is_array',
                'voGroupPrefix' => 'is_array',
                'coUserIdType' => 'is_string',
                'userIdAttribute' => 'is_string',
                'certificateDnAttribute' => 'is_string',
                'urnLegacy' => 'is_bool',
                'noRoleEntitlements' => 'is_bool',
                'certificate' => 'is_bool',
                'mergeEntitlements' => 'is_bool',
                'coTermsId' => 'is_int',
                'retrieveAUP' => 'is_bool',
                'retrieveSshKeys' => 'is_bool',
                'comanage_api_username' => 'is_string',
                'comanage_api_password' => 'is_string',
            ],
        ];
    }

    /**
     * @param $e
     * @param $parameters
     *
     * @throws Exception
     */
    private function showError($e, $parameters = NULL)
    {
        $globalConfig = Configuration::getInstance();
        $t = new Template($globalConfig, 'attrauthcomanage:exception.tpl.php');
        $t->data['e'] = $e;
        $t->data['parameters'] = (!empty($parameters) ? $parameters : "");
        $t->show();
        exit();
    }

    /**
     * @param string[]  $args
     * @param []        $state
     *
     * @example         $pt_noty = [
     *                    'level' => $pt_hdler->getBannerClass(),
     *                    'description' => $pt_hdler->getInfoHtmlElement(),
     *                    'status' => 'account_pending_confirmation', // This is a dictionary key
     *                  ];
     */
    private function showNoty($args, $state)
    {
        $state['noty'] = $args;
        $id = State::saveState($state, 'attrauthcomanage_noty_state');
        $url = Module::getModuleURL('attrauthcomanage/noty.ctrl.php');
        HTTP::redirectTrustedURL($url, ['StateId' => $id]);
    }

    private function getIdPMetadata($state)
    {
        // If the module is active on a bridge,
        // $request['saml:sp:IdP'] will contain an entry id for the remote IdP.
        if (!empty($state['saml:sp:IdP'])) {
            $idpEntityId = $state['saml:sp:IdP'];
            return MetaDataStorageHandler::getMetadataHandler()->getMetaData($idpEntityId, 'saml20-idp-remote');
        } else {
            return $state['Source'];
        }
    }

    private function getIdPTags($idpMetadata)
    {
        if (!empty($idpMetadata['tags'])) {
            return $idpMetadata['tags'];
        }

        return [];
    }
}
