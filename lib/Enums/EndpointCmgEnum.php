<?php

/**
 * Class sspmod_attrauthcomanage_Enums_EndpointCmgEnum
 *
 * COmanage Endpoints
 *
 * todo: Change const to public const for php version >=7.1
 */
class sspmod_attrauthcomanage_Enums_EndpointCmgEnum extends sspmod_attrauthcomanage_Enums_EnumAbstract
{
    const ConfirmationEmailResend       = '/co_petitions/resend/%id%';
    const EnrollmentFlow                = '/co_petitions/start/coef:%id%';
}
