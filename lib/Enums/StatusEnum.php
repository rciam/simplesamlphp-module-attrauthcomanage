<?php

namespace SimpleSAML\Module\attrauthcomanage\Enums;

/**
 * Interface StatusEnum
 *
 * User Status abbreviation
 *
 */
//class StatusEnum extends EnumAbstract
interface StatusEnum
{
    public const Active                = 'A';
    public const Approved              = 'Y';
    public const Confirmed             = 'C';
    public const Deleted               = 'D';
    public const Denied                = 'N';
    public const Duplicate             = 'D2';
    public const Expired               = 'XP';
    public const GracePeriod           = 'GP';
    public const Invited               = 'I';
    public const Pending               = 'P';
    public const PendingApproval       = 'PA';
    public const PendingConfirmation   = 'PC';
    public const Suspended             = 'S';
    public const Declined              = 'X';
}

?>
