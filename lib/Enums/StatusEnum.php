<?php
/**
 * Class sspmod_attrauthcomanage_Enums_StatusEnum
 *
 * User Status abbraviation
 *
 * todo: Change const to public const for php version >=7.1
 */
class sspmod_attrauthcomanage_Enums_StatusEnum extends sspmod_attrauthcomanage_Enums_EnumAbstract
{
    const Active                = 'A';
    const Approved              = 'Y';
    const Confirmed             = 'C';
    const Deleted               = 'D';
    const Denied                = 'N';
    const Duplicate             = 'D2';
    const Expired               = 'XP';
    const GracePeriod           = 'GP';
    const Invited               = 'I';
    const Pending               = 'P';
    const PendingApproval       = 'PA';
    const PendingConfirmation   = 'PC';
    const Suspended             = 'S';
    const Declined              = 'X';
}

?>