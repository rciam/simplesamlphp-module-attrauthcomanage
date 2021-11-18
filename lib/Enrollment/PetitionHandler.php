<?php
/**
 * This Class is a Helper class for COmanageDbClient class
 *
 * @author Nicolas Liampotis <nliam@grnet.gr>
 * @author Nick Evangelou <nikosev@grnet.gr>
 * @author Ioannis Igoumenos <ioigoume@grnet.gr>
 */

namespace SimpleSAML\Module\attrauthcomanage\Enrollment;

use PDO;
use SimpleSAML\Database;
use SimpleSAML\Error;
use SimpleSAML\Logger;

/**
 * Class PetitionHandler
 */
class PetitionHandler
{
    /**
     * @var integer|null
     */
    private $co_id = null;

    /**
     * @var integer|null
     */
    private $enrollee_co_person_id = null;

    /**
     * @var string|null
     */
    protected $resend_endpoint = null;

    /**
     * @var string|null
     */
    protected $petition_status = null;

    /**
     * @var [] |null
     */
    private $petQueryResult = null;

    /**
     * @var [] |null
     */
    private $orgIdentifier = null;

    /**
     * SQL Raw Query which retrieves User's Petition by CO Person ID and Petition Status
     *
     * The invitation token either expires or is deleted if the user accepts the invitation
     * Before Pending Confirmation status i have a petitioner_token != null enrollee_token == null
     * After Pending Confirmation status i have a petitioner_token == null enrollee_token != null
     *
     * @var string
     *
     * @covers Only CO level Petitions
     */
    protected $queryPetition = "select"
    . " ccp.id as petition_id,"
    . " ccp.enrollee_co_person_id as enrollee_co_person_id,"
    . " ccp.enrollee_token as enrollee_token,"
    . " ccp.petitioner_token as petitioner_token,"
    . " cci.mail as mail,"
    . " cci.invitation as invitation_token,"
    . " cci.deleted as invitation_is_deleted,"
    . " cci.expires as invitation_expires_date,"
    . " date_part('epoch', cci.expires)::int as invitation_expires_utimestamp,"
    . " (cci.expires - now()) as invitation_expires_string"
    . " from cm_co_petitions as ccp"
    . " inner join cm_co_invites cci on ccp.co_invite_id = cci.id and"
    . " not ccp.deleted and"
    . " ccp.co_petition_id is null and"
    . " cci.co_invite_id is null"
    . " where"
    . " ccp.enrollee_co_person_id = :enrolleeCoPersonId"
    . " and ccp.co_id = :co_id"
    . " and ccp.status = :petitionStatus"
    . " and ccp.cou_id is null;";

    /**
     * PetitionHandler constructor.
     *
     * Require the Enrollee CO Person ID, Petition Status, OrgIdentity Identifier
     *
     * @param (integer|string|string)[] $cfg        Dependency injection array - [enrollee_co_person_id,resend_endpoint,petition_status]
     */
    public function __construct($cfg)
    {
        $this->enrollee_co_person_id = empty($cfg['enrollee_co_person_id']) ?: (int)$cfg['enrollee_co_person_id'];
        $this->resend_endpoint = empty($cfg['resend_endpoint'])
                                 ? "/registry/co_petitions/resend/:PETITION_ID:"
                                 : $cfg['resend_endpoint'];
        $this->petition_status = empty($cfg['petition_status']) ?: $cfg['petition_status'];
        $this->co_id = $cfg['co_id'];
        $this->petQueryResult = $this->runQueryPetitionFromPersonIdPetStatus($this->petition_status, $this->co_id);

        $this->orgIdentifier = empty($cfg['orgIdentifier']) ?: $cfg['orgIdentifier'];

    }

    /**
     * @param string  $petition_status              Abbraviated Petition Status as defined in COmanage Registry
     * @param int     $co_id                        CO Id
     *
     * @return []                                   CO Petition Database Entry
     * @throws Exception                            Database read failed
     */
    protected function runQueryPetitionFromPersonIdPetStatus($petition_status, $co_id)
    {
        $result = [];
        $db = Database::getInstance();
        $queryParams = [
            'enrolleeCoPersonId'    => [$this->enrollee_co_person_id, PDO::PARAM_INT],
            'petitionStatus'        => [$petition_status, PDO::PARAM_STR],
            'co_id'                 => [$co_id, PDO::PARAM_INT]
        ];
        Logger::debug("[attrauthcomanage][PetitionHandler][getPetitionFormPidPs]: query="
                                 . var_export($this->queryPetition, true));
        $stmt = $db->read($this->queryPetition, $queryParams);
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            Logger::debug("[attrauthcomanage][PetitionHandler][getPetitionFormPidPs]: result="
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
     * Get the raw Data from the database Related to the Petition
     *
     * @return (integer|integer|string|string|string|string|boolean|string|integer|string)[]|null
     *
     */
    public function getPetitionFromPersonIdPetStatus() {
        return $this->petQueryResult;
    }

    /**
     * Get the Recipient Email of the CO Petition
     *
     * @return string
     */
    public function getPetitionRecipientMail() {
        return $this->petQueryResult[0]['mail'];
    }

    /**
     * Return the list of Dictionary elements to use and Values for the placeholders for each element
     *
     * @return [string[var,var]]
     */
    public function getDictionaryItems() {
        list($hr_time_expr, $expired) = $this->getExpTimeWindowAndStatus();
        $mail = $this->petQueryResult[0]['mail'];
        list($days, $hours, $minutes) = $this->extractDatefromStr();
        $date_string = $days . " days, " . $hours . " hours and " . $minutes . " minutes.";
        $dictionary_list = [];
        $dictionary_list['petition_info'] = [
            '%ORGIDENT%' => $this->orgIdentifier,
            '%MAIL%' => $mail,
        ];

        if($expired) {
            $dictionary_list['petition_token_expired'] = [
                '%DATE%' => $date_string
            ];
        } else {
            $dictionary_list['petition_token_expires'] = [
                '%DATE%' => $date_string
            ];
        }
        // Invalidation Message
        $dictionary_list['petition_invalidate_msg'] = [];

        return $dictionary_list;
    }

    /**
     * @return array
     */
    public function getUserNotify() {
        $dictionary_list = [];
        $dictionary_list['petition_user_notify'] = [
            '%MAIL%' => $this->petQueryResult[0]['mail'],
        ];
        // Invalidation Message
        $dictionary_list['petition_invalidate_msg'] = [];

        return $dictionary_list;
    }


    /**
     * Extract days, hours and minutes from a date string having the form `2 days 23:55:43.242064`
     *
     * @return [int,int,int]
     */
    private function extractDatefromStr() {
        $days = 0;
        $hours = 0;
        $minutes = 0;

        if(strpos($this->petQueryResult[0]['invitation_expires_string'], 'days') !== false) {
            $date_parts = explode(' ', $this->petQueryResult[0]['invitation_expires_string']);
            $days = $date_parts[0];
            $hms_parts = explode(':', $date_parts[2]);
            $hours = $hms_parts[0];
            $minutes = $hms_parts[1];
        }

        return [$days, $hours, $minutes];
    }

    /**
     * Returns the Noty compatible banner class according to Petition Status
     *
     * @return  string
     * @value   info|warning|success|error
     */
    public function getBannerClass() {
        list($hr_time_expr, $expired) = $this->getExpTimeWindowAndStatus();
        return ($expired) ? 'warning' : 'info';
    }

    /**
     * Calculates the expiration status from the Query data
     *
     * @return  [string,bool][]
     */
    public function getExpTimeWindowAndStatus() {
        $expires_timestamp = $this->petQueryResult[0]['invitation_expires_utimestamp'];
        $now = new \DateTime("now", new \DateTimeZone("UTC"));
        $current_timestamp = $now->getTimestamp();
        $exp_diff = $expires_timestamp - $current_timestamp;
        $expired = ($exp_diff < 0) ? true : false;

        // Human Readable Message
        $expire_date = new \DateTime($this->petQueryResult[0]['invitation_expires_date']);
        $interval = $now->diff($expire_date);
        $htime_win = $interval->format('%d days, %h hours and %i minutes');

        return [$htime_win, $expired];
    }
}

?>
