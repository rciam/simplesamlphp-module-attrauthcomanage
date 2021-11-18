<?php

declare(strict_types=1);

namespace SimpleSAML\Module\attrauthcomanage\User;

use PDO;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Database;
use SimpleSAML\Module\attrauthcomanage\Enums\OrgIdentityStatusEnum as OrgIdentityStatusEnum;

class OrgIdentity
{
    /**
     * @var
     */
    private $org_ident_list;
    /**
     * @var string
     */
    private $org_identity_identifier;

    /**
     * @var string
     */
    protected $orgIdIdentQuery = "select ident.type,"
    . " ident.identifier,"
    . " ident.login,"
    . " ident.org_identity_id,"
    . " coi.valid_from as org_valid_from,"
    . " coi.valid_through as org_valid_through,"
    . " coi.status as org_status"
    . " from cm_identifiers as ident"
    . " inner join cm_org_identities coi on ident.org_identity_id = coi.id"
    . " and not ident.deleted"
    . " and ident.identifier_id is null"
    . " and not coi.deleted and coi.org_identity_id is null"
    . " inner join cm_co_org_identity_links ccoil on coi.id = ccoil.org_identity_id"
    . " and not ccoil.deleted"
    . " and ccoil.co_org_identity_link_id is null"
    . " inner join cm_co_people ccp on ccoil.co_person_id = ccp.id"
    . " and not ccp.deleted"
    . " and ccp.co_person_id is null"
    . " where ident.type in (:coOrgIdType)"
    . ":isLogin" // XXX This is a placeholder for the entire line"
    . " and ccp.id = :coPersonId";

    /**
     * Constructor
     *
     * @param $org_identity_identifier
     */
    public function __construct($org_identity_identifier)
    {
        $this->org_identity_identifier = $org_identity_identifier;
    }

    /**
     * Fetch all the Login enabled Identifiers linked to OrgIdentities. Define whether these identifiers are authenticators or not
     *
     * @param   string  $personId  The CO Person ID
     * @param   array   $orgIdentTypeList
     *
     * @return array|null Return an array of identifiers, column headers [ident.type, ident.identifier, ident.login, ident.org_identity_id]
     * @throws Exception
     */
    public function getLoginOrgIdentifiers($personId, $orgIdentTypeList)
    {
        $this->org_ident_list = $this->getOrgIdentifiers($personId, $orgIdentTypeList, true);

        return $this->org_ident_list;
    }

    /**
     * Fetch all the NON Login Identifiers linked to OrgIdentities. Define whether these identifiers are authenticators or not
     *
     * @param   string  $personId  The CO Person ID
     * @param   array   $orgIdentTypeList
     *
     * @return array|null Return an array of identifiers, column headers [ident.type, ident.identifier, ident.login, ident.org_identity_id]
     * @throws Exception
     */
    public function getNonLoginOrgIdentifiers($personId, $orgIdentTypeList)
    {
        $this->org_ident_list = $this->getOrgIdentifiers($personId, $orgIdentTypeList, false);

        return $this->org_ident_list;
    }

    /**
     * Fetch all the Identifiers linked to OrgIdentities. Define whether these identifiers are authenticators or not
     *
     * @param   string  $personId  The CO Person ID
     * @param   array   $orgIdentTypeList
     * @param   bool    $isLogin   , true, false or null are allowed
     *
     * @return array|null Return an array of identifiers, column headers [ident.type, ident.identifier, ident.login, ident.org_identity_id]
     * @throws Exception
     */
    private function getOrgIdentifiers($personId, $orgIdentTypeList, $isLogin = null)
    {
        Logger::debug('[attrauthcomanage] getOrgIdentifiers: personId=' . var_export($personId, true));

        $db                    = Database::getInstance();
        $this->orgIdIdentQuery = str_replace(
            ':coOrgIdType',
            "'" . implode("','", $orgIdentTypeList) . "'",
            $this->orgIdIdentQuery
        );
        if (is_null($isLogin)) {
            $isLoginConditionStr = '';
        } else {
            $isLoginCondition    = ($isLogin) ? 'true' : 'false';
            $isLoginConditionStr = ' and ident.login=' . $isLoginCondition;
        }

        $this->orgIdIdentQuery = str_replace(
            ':isLogin',
            $isLoginConditionStr,
            $this->orgIdIdentQuery
        );
        $queryParams           = [
            'coPersonId' => [$personId, PDO::PARAM_INT],
        ];
        $stmt                  = $db->read($this->orgIdIdentQuery, $queryParams);

        if ($stmt->execute()) {
            if ($result = $stmt->fetchall(PDO::FETCH_GROUP | PDO::FETCH_ASSOC)) {
                Logger::debug(
                    "[attrauthcomanage] getOrgIdentifiers: result="
                    . var_export($result, true)
                );

                return $result;
            }
        } else {
            throw new Error\Error(
                [
                    'UNHANDLEDEXCEPTION',
                    'Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true)
                ]
            );
        }

        return null;
    }

    /**
     * Check whether the identifier fetched from the IdP is available in the list of my Identifiers
     * and marked as a login identifier
     *
     * @return bool
     */
    public function isIdpIdentLogin(): bool
    {
        if (empty($this->org_ident_list) || empty($this->org_identity_identifier)) {
            return false;
        }
        foreach ($this->org_ident_list as $identifierTypes) {
            foreach ($identifierTypes as $ident) {
                if ($ident['identifier'] === $this->org_identity_identifier
                    && $ident['login']) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check whether the identifier fetched from the IdP is available in the list of my Identifiers
     * and marked as Removed
     *
     * @return bool
     */
    public function isIdpRemoved(): bool
    {
        if (empty($this->org_ident_list) || empty($this->org_identity_identifier)) {
            return false;
        }
        foreach ($this->org_ident_list as $identifierTypes) {
            foreach ($identifierTypes as $ident) {
                if ($ident['identifier'] === $this->org_identity_identifier
                    && $ident['org_status'] == OrgIdentityStatusEnum::Removed) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check whether the identifier fetched from the IdP has expired
     * If valid from and valid through fields are empty we assume that the Identifier will never expire
     *
     * @return bool|null true(is expired), false(is not expired), null if either of the parameters are empty
     * @throws Exception
     * @todo make timezone configuration
     */
    public function isIdpIdentExpired()
    {
        if (empty($this->org_ident_list) || empty($this->org_identity_identifier)) {
            return null;
        }
        foreach ($this->org_ident_list as $identifierTypes) {
            foreach ($identifierTypes as $ident) {
                if ($ident['identifier'] === $this->org_identity_identifier) {
                    $current_date = new \DateTime('now', new \DateTimeZone('Etc/UTC'));
                    if (empty($ident['org_valid_from']) && empty($ident['org_valid_through'])) {
                        return false;
                    } elseif (empty($ident['org_valid_from']) && !empty($ident['org_valid_through'])) {
                        $valid_through = new \DateTime($ident['org_valid_through'], new \DateTimeZone('Etc/UTC'));

                        return !($valid_through >= $current_date);
                    } elseif (!empty($ident['org_valid_from']) && empty($ident['org_valid_through'])) {
                        $valid_from = new \DateTime($ident['org_valid_from'], new \DateTimeZone('Etc/UTC'));

                        return !($current_date >= $valid_from);
                    } elseif (!empty($ident['org_valid_from']) && !empty($ident['org_valid_through'])) {
                        $valid_from    = new \DateTime($ident['org_valid_from'], new \DateTimeZone('Etc/UTC'));
                        $valid_through = new \DateTime($ident['org_valid_through'], new \DateTimeZone('Etc/UTC'));
                        if ($valid_through >= $current_date
                            && $current_date > $valid_from) {
                            return false;
                        } else {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }
}