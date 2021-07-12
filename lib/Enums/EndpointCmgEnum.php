<?php

namespace SimpleSAML\Module\attrauthcomanage\Enums;

/**
 * Interface EndpointCmgEnum
 *
 * COmanage Endpoints
 *
 */
interface EndpointCmgEnum
{
    public const ConfirmationEmailResend       = '/co_petitions/resend/%id%';
    public const EnrollmentFlow                = '/co_petitions/start/coef:%id%';
}
