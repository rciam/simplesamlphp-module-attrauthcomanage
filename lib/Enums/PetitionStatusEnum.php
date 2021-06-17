<?php

namespace SimpleSAML\Module\attrauthcomanage\Enums;

/**
 * Interface PetitionStatusEnum
 *
 * Petition abbreviation
 *
 */
interface PetitionStatusEnum
{
    public const Active                = 'A';
    public const Approved              = 'Y';
    public const Confirmed             = 'C';
    public const Created               = 'CR';
    public const Declined              = 'X';
    public const Denied                = 'N';
    public const Duplicate             = 'D2';
    public const Finalized             = 'F';
    public const PendingApproval       = 'PA';
    public const PendingConfirmation   = 'PC';
}
