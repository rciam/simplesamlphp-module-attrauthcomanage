<?php

/**
 * Class sspmod_attrauthcomanage_Actions_PetitionHandler
 */
class sspmod_attrauthcomanage_Enrollment_PetitionHandler
{
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
     * @var array|null
     */
    private $petQueryResult = null;

    /**
     * @var array|null
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
    . " and ccp.status = :petitionStatus"
    . " and ccp.cou_id is null;";

    /**
     * sspmod_attrauthcomanage_Actions_PetitionHandler constructor.
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
        $this->petQueryResult = $this->runQueryPetitionFromPersonIdPetStatus($this->petition_status);

        $this->orgIdentifier = empty($cfg['orgIdentifier']) ?: $cfg['orgIdentifier'];

    }

    /**
     * @param string  $petition_status              Abbraviated Petition Status as defined in COmanage Registry
     *
     * @return array                                CO Petition Database Entry
     * @throws Exception                            Database read failed
     */
    protected function runQueryPetitionFromPersonIdPetStatus($petition_status)
    {
        $result = array();
        $db = SimpleSAML\Database::getInstance();
        $queryParams = array(
            'enrolleeCoPersonId' => array($this->enrollee_co_person_id, PDO::PARAM_INT),
            'petitionStatus' => array($petition_status, PDO::PARAM_STR),
        );
        SimpleSAML_Logger::debug("[attrauthcomanage][PetitionHandler][getPetitionFormPidPs]: query="
                                 . var_export($this->queryPetition, true));
        $stmt = $db->read($this->queryPetition, $queryParams);
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            SimpleSAML_Logger::debug("[attrauthcomanage][PetitionHandler][getPetitionFormPidPs]: result="
                                     . var_export($result, true));
            return $result;
        } else {
            throw new Exception('Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true));
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
     *
     */
    public function getInfoHtmlElement() {
        list($hr_time_expr, $expired) = $this->getExpTimeWindowAndStatus();
        $mail = $this->petQueryResult[0]['mail'];

        $info_msg = 'The identifier <cite><b>' . $this->orgIdentifier . '</b></cite> is in Email Pending Confirmation Status.&nbsp';
        $info_msg .= 'Please check your Mail <cite><b>' . $mail . '</b></cite> Inbox or Spam for further information.&nbsp';
        if($expired) {
            $info_msg .= '<div class="invite-expire">Email confirmation token EXPIRED <b>&nbsp' . $hr_time_expr . '</b>&nbspago</div>';
        } else {
            $info_msg .= '<div class="invite-expire">Email confirmation token EXPIRES in <b>&nbsp' . $hr_time_expr . '</b></div>';
        }

        return $info_msg;
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
        $exp_timestamp = $this->petQueryResult[0]['invitation_expires_utimestamp'];
        $now = new DateTime();
        $current_timestamp = $now->getTimestamp();
        $exp_diff = $expires_timestamp - $current_timestamp;
        $expired = ($exp_diff < 0) ? true : false;

        // Human Readable Message
        $expire_date = new DateTime($this->petQueryResult[0]['invitation_expires_date']);
        $interval = $now->diff($expire_date);
        $htime_win = $interval->format('%d days, %h hours and %i minutes');

        return array($htime_win, $expired);
    }
}

?>